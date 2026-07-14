"""IDS sensor ingestion: Suricata EVE JSON and Zeek logs.

If you run Suricata or Zeek on a mirror/SPAN port (the "sensor mode" from the
project roadmap), point NetScope at their output and their alerts surface in the
dashboard. Everything here fails soft: missing files simply yield no alerts.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from ..config import settings
from ..core.netutil import is_private_ip


@dataclass
class IdsAlert:
    ts: str = ""
    source: str = ""       # "suricata" | "zeek"
    severity: str = "info"  # info | warning | critical
    signature: str = ""
    src_ip: str = ""
    dest_ip: str = ""
    category: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


# Track byte offsets so repeated polls only read new lines.
_offsets: dict[str, int] = {}


def _severity_from_suricata(sev: int) -> str:
    if sev <= 1:
        return "critical"
    if sev == 2:
        return "warning"
    return "info"


def read_suricata_alerts(path: str | None = None, limit: int = 200) -> list[IdsAlert]:
    path = path or settings.suricata_eve_path
    if not path or not os.path.exists(path):
        return []
    alerts: list[IdsAlert] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or '"event_type":"alert"' not in line.replace(" ", ""):
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if ev.get("event_type") != "alert":
                    continue
                a = ev.get("alert", {})
                alerts.append(
                    IdsAlert(
                        ts=ev.get("timestamp", ""),
                        source="suricata",
                        severity=_severity_from_suricata(int(a.get("severity", 3))),
                        signature=a.get("signature", ""),
                        src_ip=ev.get("src_ip", ""),
                        dest_ip=ev.get("dest_ip", ""),
                        category=a.get("category", ""),
                    )
                )
    except Exception:
        return alerts[-limit:]
    return alerts[-limit:]


def read_zeek_notices(log_dir: str | None = None, limit: int = 200) -> list[IdsAlert]:
    log_dir = log_dir or settings.zeek_log_dir
    if not log_dir or not os.path.isdir(log_dir):
        return []
    notice_path = os.path.join(log_dir, "notice.log")
    if not os.path.exists(notice_path):
        return []
    alerts: list[IdsAlert] = []
    fields: list[str] = []
    try:
        with open(notice_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]
                    continue
                if line.startswith("#") or not line.strip():
                    continue
                cols = line.rstrip("\n").split("\t")
                row = dict(zip(fields, cols)) if fields else {}
                alerts.append(
                    IdsAlert(
                        ts=row.get("ts", ""),
                        source="zeek",
                        severity="warning",
                        signature=row.get("note", "") or row.get("msg", ""),
                        src_ip=row.get("id.orig_h", ""),
                        dest_ip=row.get("id.resp_h", ""),
                        category=row.get("note", ""),
                    )
                )
    except Exception:
        return alerts[-limit:]
    return alerts[-limit:]


def all_alerts(limit: int = 200) -> list[dict]:
    combined = read_suricata_alerts(limit=limit) + read_zeek_notices(limit=limit)
    combined.sort(key=lambda a: a.ts, reverse=True)
    return [a.to_dict() for a in combined[:limit]]


def configured() -> bool:
    return bool(settings.suricata_eve_path or settings.zeek_log_dir)


# --------------------------------------------------------------------------- #
# Zeek TSV log ingestion (conn.log / dns.log) -> flow store + DNS analytics
# --------------------------------------------------------------------------- #
def _is_local(ip: str) -> bool:
    return is_private_ip(ip)


def _read_new_zeek_rows(path: str) -> list[dict]:
    """Return newly-appended rows of a Zeek TSV log (offset-tracked)."""
    if not path or not os.path.exists(path):
        return []
    rows: list[dict] = []
    fields: list[str] = []
    try:
        size = os.path.getsize(path)
        # Read from the start on first sight (ingest history), then only new data.
        start = _offsets.get(path, 0)
        if size < start:  # log rotated / truncated
            start = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]
                    break
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            fh.seek(start)
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                cols = line.rstrip("\n").split("\t")
                if fields and len(cols) >= len(fields):
                    rows.append(dict(zip(fields, cols)))
            _offsets[path] = fh.tell()
    except Exception:
        return rows
    return rows


def poll_new_conn_flows() -> list[dict]:
    """New Zeek conn.log rows normalized to flow dicts (whole-network flows)."""
    if not settings.zeek_log_dir:
        return []
    path = os.path.join(settings.zeek_log_dir, "conn.log")
    out: list[dict] = []
    for r in _read_new_zeek_rows(path):
        orig, resp = r.get("id.orig_h", ""), r.get("id.resp_h", "")
        if not resp:
            continue
        # Orient the flow so "remote" is the non-local side when possible.
        if _is_local(orig) or not _is_local(resp):
            local, remote, rport = orig, resp, r.get("id.resp_p", "0")
            bs, br = r.get("orig_bytes", "0"), r.get("resp_bytes", "0")
        else:
            local, remote, rport = resp, orig, r.get("id.orig_p", "0")
            bs, br = r.get("resp_bytes", "0"), r.get("orig_bytes", "0")
        out.append({
            "local_ip": local, "remote_ip": remote,
            "remote_port": _to_int(rport), "protocol": r.get("proto", "tcp"),
            "bytes_sent": _to_int(bs), "bytes_recv": _to_int(br),
        })
    return out


def poll_new_http() -> list[dict]:
    """New Zeek http.log rows -> [{ip, user_agent}] for User-Agent identification."""
    if not settings.zeek_log_dir:
        return []
    path = os.path.join(settings.zeek_log_dir, "http.log")
    out = []
    for r in _read_new_zeek_rows(path):
        ua = r.get("user_agent", "").strip()
        ip = r.get("id.orig_h", "").strip()
        if ua and ua != "-" and ip:
            out.append({"ip": ip, "user_agent": ua})
    return out


def poll_new_dns_names() -> list[str]:
    """New domains from Zeek dns.log."""
    if not settings.zeek_log_dir:
        return []
    path = os.path.join(settings.zeek_log_dir, "dns.log")
    names = []
    for r in _read_new_zeek_rows(path):
        q = r.get("query", "").strip(".")
        if q and not q.endswith((".local", ".arpa")):
            names.append(q)
    return names


def _to_int(v) -> int:
    try:
        return int(float(v)) if v not in ("", "-") else 0
    except Exception:
        return 0


def poll_new_alerts() -> list[IdsAlert]:
    """Return only alerts appended since the last poll (by file offset)."""
    new: list[IdsAlert] = []
    path = settings.suricata_eve_path
    if path and os.path.exists(path):
        try:
            size = os.path.getsize(path)
            start = _offsets.get(path, size)  # first poll: skip existing history
            if size < start:  # file rotated/truncated
                start = 0
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                fh.seek(start)
                for line in fh:
                    if '"event_type":"alert"' not in line.replace(" ", ""):
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue
                    if ev.get("event_type") != "alert":
                        continue
                    a = ev.get("alert", {})
                    new.append(
                        IdsAlert(
                            ts=ev.get("timestamp", ""),
                            source="suricata",
                            severity=_severity_from_suricata(int(a.get("severity", 3))),
                            signature=a.get("signature", ""),
                            src_ip=ev.get("src_ip", ""),
                            dest_ip=ev.get("dest_ip", ""),
                            category=a.get("category", ""),
                        )
                    )
                _offsets[path] = fh.tell()
        except Exception:
            pass
    return new
