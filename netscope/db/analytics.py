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
                samples     BIGINT
            )
            """
        )


def available() -> bool:
    return _conn is not None


def _is_local(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "172.", "169.254.", "127."))


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
                    "INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [key, lip, rip, rport, proto, proc, is_local, ts, ts, 1],
                )
                new_count += 1
    return new_count


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
