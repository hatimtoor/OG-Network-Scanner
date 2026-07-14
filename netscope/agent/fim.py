"""File Integrity Monitoring (FIM).

Watches configured paths (files or directories), hashes their contents, and
reports added / modified / deleted files against a stored baseline. Baseline is a
JSON file next to the database. The first scan just establishes the baseline
(no alerts). Watched paths: NETSCOPE_FIM_PATHS (comma-separated).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from ..config import settings

_BASELINE = Path(settings.db_path).resolve().parent / "fim_baseline.json"
_MAX_FILE = 50 * 1024 * 1024  # skip files larger than 50MB


def _watched_paths() -> list[str]:
    return [p.strip() for p in settings.fim_paths.split(",") if p.strip()]


def _hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _scan_paths(paths: list[str]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for base in paths:
        if os.path.isfile(base):
            files = [base]
        elif os.path.isdir(base):
            files = []
            for root, _dirs, names in os.walk(base):
                for n in names:
                    files.append(os.path.join(root, n))
        else:
            continue
        for f in files:
            try:
                st = os.stat(f)
                if st.st_size > _MAX_FILE:
                    continue
                result[f] = {"sha256": _hash(f), "size": st.st_size,
                             "mtime": int(st.st_mtime)}
            except Exception:
                continue
    return result


def _load() -> dict:
    try:
        return json.loads(_BASELINE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(data: dict) -> None:
    try:
        _BASELINE.write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass


def configured() -> bool:
    return bool(_watched_paths())


def status() -> dict:
    baseline = _load()
    return {
        "configured": configured(),
        "watched_paths": _watched_paths(),
        "baseline_files": len(baseline),
        "baseline_exists": _BASELINE.exists(),
    }


def scan() -> dict:
    """Run a FIM scan; returns changes and updates the baseline."""
    paths = _watched_paths()
    if not paths:
        return {"configured": False, "added": [], "modified": [], "deleted": [],
                "first_run": False, "watched": 0}
    current = _scan_paths(paths)
    baseline = _load()
    first_run = not baseline

    added = sorted(p for p in current if p not in baseline)
    deleted = sorted(p for p in baseline if p not in current)
    modified = sorted(
        p for p in current if p in baseline
        and current[p]["sha256"] != baseline[p]["sha256"]
    )
    _save(current)
    return {
        "configured": True, "first_run": first_run,
        "added": added, "modified": modified, "deleted": deleted,
        "watched": len(current),
    }
