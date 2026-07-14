"""DuckDB analytics store for network flows (the hunting/detection substrate).

Per the PRD decision, transactional state stays in SQLite while high-volume,
query-heavy flow data lives here in an embedded columnar DuckDB store. A flow is
a (local endpoint, process) -> (remote ip:port) pair observed over time, with
first/last-seen and an observation count.

A single connection guarded by a lock is used (DuckDB allows one read-write
connection); our volume is modest so serialized access is fine.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from ..config import settings
from ..core.netutil import is_private_ip

try:
    import duckdb
except Exception:  # pragma: no cover
    duckdb = None

_conn = None
_lock = threading.Lock()


def _now() -> datetime:
    # Naive UTC: DuckDB's TIMESTAMPTZ ops require the optional pytz module, which
    # we avoid by storing plain UTC timestamps.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def init() -> None:
    global _conn
    if duckdb is None:
        return
    with _lock:
        if _conn is not None:
            return
        _conn = duckdb.connect(settings.analytics_path)
        _conn.execute(
            """
            CREATE TABLE IF NOT EXISTS flows (
                flow_key    VARCHAR PRIMARY KEY,
                local_ip    VARCHAR,
                remote_ip   VARCHAR,
                remote_port INTEGER,
                protocol    VARCHAR,
                process     VARCHAR,
                remote_is_local BOOLEAN,
                first_seen  TIMESTAMP,
                last_seen   TIMESTAMP,
                samples     BIGINT,
                bytes_sent  BIGINT DEFAULT 0,
                bytes_recv  BIGINT DEFAULT 0,
                source      VARCHAR DEFAULT 'host'
            )
            """
        )
        # Migrate older flow databases missing the newer columns.
        cols = {
            r[0] for r in _conn.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name='flows'"
            ).fetchall()
        }
        for name, ddl in {
            "bytes_sent": "BIGINT DEFAULT 0", "bytes_recv": "BIGINT DEFAULT 0",
            "source": "VARCHAR DEFAULT 'host'",
        }.items():
            if name not in cols:
                _conn.execute(f"ALTER TABLE flows ADD COLUMN {name} {ddl}")

        # Indexed packets from captured PCAPs (mini-Arkime search).
        _conn.execute(
            """CREATE TABLE IF NOT EXISTS packets (
                ts TIMESTAMP, src_ip VARCHAR, dst_ip VARCHAR,
                src_port INTEGER, dst_port INTEGER, protocol VARCHAR,
                length INTEGER, source_file VARCHAR, pkt_no BIGINT
            )"""
        )


def available() -> bool:
    return _conn is not None


def _is_local(ip: str) -> bool:
    return is_private_ip(ip)


def record_connections(connections: list) -> int:
    """Upsert a snapshot of connections into the flow store. Returns new-flow count."""
    if _conn is None or not connections:
        return 0
    now = _now()
    rows = []
    for c in connections:
        rip = getattr(c, "remote_ip", "") or ""
        if not rip:
            continue
        rport = int(getattr(c, "remote_port", 0) or 0)
        local = getattr(c, "local", "") or ""
        proc = getattr(c, "process", "") or ""
        lip = local.rsplit(":", 1)[0] if ":" in local else local
        key = f"{lip}|{rip}|{rport}|{proc}"
        rows.append((key, lip, rip, rport, "tcp", proc, _is_local(rip), now))

    new_count = 0
    with _lock:
        for key, lip, rip, rport, proto, proc, is_local, ts in rows:
            existing = _conn.execute(
                "SELECT samples FROM flows WHERE flow_key = ?", [key]
            ).fetchone()
            if existing:
                _conn.execute(
                    "UPDATE flows SET last_seen = ?, samples = samples + 1 WHERE flow_key = ?",
                    [ts, key],
                )
            else:
                _conn.execute(
                    """INSERT INTO flows
                       (flow_key, local_ip, remote_ip, remote_port, protocol, process,
                        remote_is_local, first_seen, last_seen, samples, bytes_sent,
                        bytes_recv, source)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    [key, lip, rip, rport, proto, proc, is_local, ts, ts, 1, 0, 0, "host"],
                )
                new_count += 1
    return new_count


def record_zeek_flows(rows: list[dict]) -> int:
    """Ingest Zeek conn.log rows as network-wide flows (with byte counts)."""
    if _conn is None or not rows:
        return 0
    now = _now()
    new_count = 0
    with _lock:
        for r in rows:
            lip = r.get("local_ip", "")
            rip = r.get("remote_ip", "")
            if not rip:
                continue
            rport = int(r.get("remote_port", 0) or 0)
            proto = r.get("protocol", "") or "tcp"
            key = f"zeek|{lip}|{rip}|{rport}"
            bs = int(r.get("bytes_sent", 0) or 0)
            br = int(r.get("bytes_recv", 0) or 0)
            existing = _conn.execute("SELECT samples FROM flows WHERE flow_key = ?", [key]).fetchone()
            if existing:
                _conn.execute(
                    """UPDATE flows SET last_seen = ?, samples = samples + 1,
                       bytes_sent = bytes_sent + ?, bytes_recv = bytes_recv + ?
                       WHERE flow_key = ?""",
                    [now, bs, br, key],
                )
            else:
                _conn.execute(
                    """INSERT INTO flows
                       (flow_key, local_ip, remote_ip, remote_port, protocol, process,
                        remote_is_local, first_seen, last_seen, samples, bytes_sent,
                        bytes_recv, source)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    [key, lip, rip, rport, proto, "", _is_local(rip), now, now, 1, bs, br, "zeek"],
                )
                new_count += 1
    return new_count


def device_profiles() -> dict[str, dict]:
    """Per-device 'pattern of life': the external ports and remote-count it uses."""
    if _conn is None:
        return {}
    with _lock:
        rows = _conn.execute(
            """SELECT local_ip,
                      list(DISTINCT remote_port) AS ports,
                      COUNT(DISTINCT remote_ip) AS remotes
               FROM flows WHERE remote_is_local = FALSE AND local_ip <> ''
               GROUP BY local_ip"""
        ).fetchall()
    return {r[0]: {"ports": sorted(int(p) for p in (r[1] or [])), "remotes": int(r[2] or 0)}
            for r in rows}


def device_bandwidth(limit: int = 50) -> list[dict]:
    """Per-device byte totals grouped by local IP (whole-network with a Zeek sensor)."""
    if _conn is None:
        return []
    with _lock:
        rows = _conn.execute(
            """SELECT local_ip, SUM(bytes_sent) AS sent, SUM(bytes_recv) AS recv,
                      COUNT(*) AS flows
               FROM flows WHERE local_ip <> ''
               GROUP BY local_ip
               ORDER BY (SUM(bytes_sent) + SUM(bytes_recv)) DESC LIMIT ?""",
            [limit],
        ).fetchall()
    return [{"ip": r[0], "bytes_sent": int(r[1] or 0), "bytes_recv": int(r[2] or 0),
             "flows": r[3]} for r in rows]


def exfil_candidates(min_bytes: int = 50_000_000) -> list[dict]:
    """External flows with large upload volume (possible data exfiltration)."""
    if _conn is None:
        return []
    with _lock:
        rows = _conn.execute(
            """SELECT local_ip, remote_ip, remote_port, process, bytes_sent
               FROM flows WHERE remote_is_local = FALSE AND bytes_sent >= ?
               ORDER BY bytes_sent DESC LIMIT 20""",
            [min_bytes],
        ).fetchall()
    return [{"local_ip": r[0], "remote_ip": r[1], "remote_port": r[2],
             "process": r[3], "bytes_sent": r[4]} for r in rows]


def query_flows(
    remote_ip: str = "", process: str = "", port: int | None = None,
    external_only: bool = False, search: str = "", limit: int = 200,
) -> list[dict]:
    if _conn is None:
        return []
    where = []
    params: list = []
    if remote_ip:
        where.append("remote_ip = ?"); params.append(remote_ip)
    if process:
        where.append("lower(process) LIKE ?"); params.append(f"%{process.lower()}%")
    if port is not None:
        where.append("remote_port = ?"); params.append(port)
    if external_only:
        where.append("remote_is_local = FALSE")
    if search:
        where.append("(lower(process) LIKE ? OR remote_ip LIKE ? OR local_ip LIKE ?)")
        s = f"%{search.lower()}%"; params += [s, s, s]
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    with _lock:
        rows = _conn.execute(
            f"""SELECT local_ip, remote_ip, remote_port, protocol, process,
                       remote_is_local, first_seen, last_seen, samples
                FROM flows {clause} ORDER BY last_seen DESC LIMIT ?""",
            params + [limit],
        ).fetchall()
    return [
        {
            "local_ip": r[0], "remote_ip": r[1], "remote_port": r[2], "protocol": r[3],
            "process": r[4], "remote_is_local": r[5],
            "first_seen": r[6].isoformat() if r[6] else None,
            "last_seen": r[7].isoformat() if r[7] else None,
            "samples": r[8],
        }
        for r in rows
    ]


def top_talkers(limit: int = 15, external_only: bool = True) -> list[dict]:
    if _conn is None:
        return []
    clause = "WHERE remote_is_local = FALSE" if external_only else ""
    with _lock:
        rows = _conn.execute(
            f"""SELECT remote_ip, SUM(samples) AS total, COUNT(*) AS flows,
                       MAX(last_seen) AS last
                FROM flows {clause}
                GROUP BY remote_ip ORDER BY total DESC LIMIT ?""",
            [limit],
        ).fetchall()
    return [
        {"remote_ip": r[0], "samples": r[1], "flows": r[2],
         "last_seen": r[3].isoformat() if r[3] else None}
        for r in rows
    ]


def stats() -> dict:
    if _conn is None:
        return {"available": False}
    with _lock:
        total = _conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        remotes = _conn.execute("SELECT COUNT(DISTINCT remote_ip) FROM flows").fetchone()[0]
        external = _conn.execute(
            "SELECT COUNT(*) FROM flows WHERE remote_is_local = FALSE"
        ).fetchone()[0]
        ports = _conn.execute(
            """SELECT remote_port, COUNT(*) c FROM flows WHERE remote_is_local = FALSE
               GROUP BY remote_port ORDER BY c DESC LIMIT 8"""
        ).fetchall()
    return {
        "available": True,
        "total_flows": total,
        "distinct_remotes": remotes,
        "external_flows": external,
        "top_ports": [{"port": p[0], "count": p[1]} for p in ports],
    }


def scan_candidates(min_remotes: int = 20) -> list[dict]:
    """Processes/hosts contacting many distinct external IPs (horizontal scan)."""
    if _conn is None:
        return []
    with _lock:
        rows = _conn.execute(
            """SELECT process, local_ip, COUNT(DISTINCT remote_ip) AS remotes
               FROM flows WHERE remote_is_local = FALSE
               GROUP BY process, local_ip HAVING remotes >= ?
               ORDER BY remotes DESC LIMIT 20""",
            [min_remotes],
        ).fetchall()
    return [{"process": r[0], "local_ip": r[1], "remotes": r[2]} for r in rows]


def vertical_scan_candidates(min_ports: int = 15) -> list[dict]:
    """A single remote hit on many distinct ports (vertical/port scan)."""
    if _conn is None:
        return []
    with _lock:
        rows = _conn.execute(
            """SELECT process, local_ip, remote_ip, COUNT(DISTINCT remote_port) AS ports
               FROM flows GROUP BY process, local_ip, remote_ip
               HAVING ports >= ? ORDER BY ports DESC LIMIT 20""",
            [min_ports],
        ).fetchall()
    return [{"process": r[0], "local_ip": r[1], "remote_ip": r[2], "ports": r[3]} for r in rows]


def beacon_candidates(min_samples: int = 30, min_duration_s: int = 600) -> list[dict]:
    """External flows seen many times over a long window (steady = possible beacon)."""
    if _conn is None:
        return []
    with _lock:
        rows = _conn.execute(
            """SELECT process, local_ip, remote_ip, remote_port, samples,
                      date_diff('second', first_seen, last_seen) AS dur
               FROM flows
               WHERE remote_is_local = FALSE AND samples >= ?
                 AND date_diff('second', first_seen, last_seen) >= ?
               ORDER BY samples DESC LIMIT 30""",
            [min_samples, min_duration_s],
        ).fetchall()
    return [
        {"process": r[0], "local_ip": r[1], "remote_ip": r[2], "remote_port": r[3],
         "samples": r[4], "duration_s": r[5]}
        for r in rows
    ]


# --------------------------------------------------------------------------- #
# Packet index (from captured PCAPs)
# --------------------------------------------------------------------------- #
def record_packets(rows: list[tuple]) -> int:
    """Bulk-insert parsed packet rows (ts, src, dst, sport, dport, proto, len, file, no)."""
    if _conn is None or not rows:
        return 0
    with _lock:
        _conn.executemany(
            "INSERT INTO packets VALUES (?,?,?,?,?,?,?,?,?)", rows
        )
    return len(rows)


def indexed_pcap_files() -> list[str]:
    if _conn is None:
        return []
    with _lock:
        return [r[0] for r in _conn.execute(
            "SELECT DISTINCT source_file FROM packets").fetchall()]


def search_packets(ip: str = "", port: int | None = None, protocol: str = "",
                   source_file: str = "", limit: int = 300) -> list[dict]:
    if _conn is None:
        return []
    where, params = [], []
    if ip:
        where.append("(src_ip = ? OR dst_ip = ?)"); params += [ip, ip]
    if port is not None:
        where.append("(src_port = ? OR dst_port = ?)"); params += [port, port]
    if protocol:
        where.append("protocol = ?"); params.append(protocol.upper())
    if source_file:
        where.append("source_file = ?"); params.append(source_file)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    with _lock:
        rows = _conn.execute(
            f"""SELECT ts, src_ip, dst_ip, src_port, dst_port, protocol, length, source_file
                FROM packets {clause} ORDER BY ts DESC LIMIT ?""",
            params + [limit],
        ).fetchall()
    return [
        {"ts": r[0].isoformat() if r[0] else None, "src_ip": r[1], "dst_ip": r[2],
         "src_port": r[3], "dst_port": r[4], "protocol": r[5], "length": r[6],
         "source_file": r[7]}
        for r in rows
    ]


def packet_stats() -> dict:
    if _conn is None:
        return {"total": 0, "files": 0}
    with _lock:
        total = _conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        files = _conn.execute("SELECT COUNT(DISTINCT source_file) FROM packets").fetchone()[0]
        protos = _conn.execute(
            "SELECT protocol, COUNT(*) c FROM packets GROUP BY protocol ORDER BY c DESC LIMIT 6"
        ).fetchall()
    return {"total": total, "files": files,
            "protocols": [{"protocol": p[0], "count": p[1]} for p in protos]}


def prune(retention_days: int | None = None) -> int:
    if _conn is None:
        return 0
    days = retention_days if retention_days is not None else settings.flow_retention_days
    cutoff = _now() - timedelta(days=days)
    with _lock:
        before = _conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        _conn.execute("DELETE FROM flows WHERE last_seen < ?", [cutoff])
        after = _conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    return before - after
