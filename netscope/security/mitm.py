"""Decrypted-HTTPS visibility via mitmproxy ingestion (the guide's TLS decryption).

True TLS decryption requires a man-in-the-middle proxy the clients trust — the
same mechanism an NGFW uses. NetScope does not itself decrypt traffic; instead
you run **mitmproxy** with the bundled addon (scripts/mitm-jsonl-addon.py), which
writes one JSON line per request to a log. NetScope reads that log to surface the
decrypted host/path/User-Agent per client. Configure NETSCOPE_MITM_LOG.
"""
from __future__ import annotations

import json
import os

from ..config import settings

_offsets: dict[str, int] = {}


def configured() -> bool:
    return bool(settings.mitm_log)


def poll_new_flows() -> list[dict]:
    """Return newly-appended decrypted request records (offset-tracked)."""
    path = settings.mitm_log
    if not path or not os.path.exists(path):
        return []
    out: list[dict] = []
    try:
        size = os.path.getsize(path)
        start = _offsets.get(path, 0)
        if size < start:
            start = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            fh.seek(start)
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                out.append({
                    "client": rec.get("client", ""),
                    "host": (rec.get("host", "") or "").lower().strip("."),
                    "method": rec.get("method", ""),
                    "path": rec.get("path", ""),
                    "status": rec.get("status", 0),
                    "user_agent": rec.get("user_agent", ""),
                    "scheme": rec.get("scheme", ""),
                })
            _offsets[path] = fh.tell()
    except Exception:
        return out
    return out
