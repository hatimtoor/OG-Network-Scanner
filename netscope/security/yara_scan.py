"""File scanning: SHA-256 hashing, VirusTotal hash reputation, and YARA rules.

YARA (``yara-python``) is optional — install it and point NETSCOPE_YARA_RULES at
a ``.yar`` file to enable local pattern matching. Even without YARA, this module
hashes files and checks their reputation on VirusTotal, which catches known
malware by hash alone.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

from ..config import settings
from . import threatintel

try:
    import yara  # type: ignore

    _YARA = True
except Exception:
    _YARA = False

_compiled = None
_compiled_path = ""


@dataclass
class FileScanResult:
    file: str
    sha256: str = ""
    size: int = 0
    yara_matches: list[str] = field(default_factory=list)
    vt_verdict: str = "unknown"
    vt_detail: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


def yara_available() -> bool:
    return _YARA and bool(settings.yara_rules_path) and os.path.exists(settings.yara_rules_path)


def _get_rules():
    global _compiled, _compiled_path
    if not yara_available():
        return None
    if _compiled is not None and _compiled_path == settings.yara_rules_path:
        return _compiled
    try:
        _compiled = yara.compile(filepath=settings.yara_rules_path)
        _compiled_path = settings.yara_rules_path
        return _compiled
    except Exception:
        return None


def hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_file(path: str, check_vt: bool = True) -> FileScanResult:
    if not os.path.isfile(path):
        return FileScanResult(file=path, error="file not found")
    result = FileScanResult(file=path)
    try:
        result.size = os.path.getsize(path)
        result.sha256 = hash_file(path)
    except Exception as exc:
        result.error = f"read error: {exc}"
        return result

    rules = _get_rules()
    if rules is not None:
        try:
            matches = rules.match(path)
            result.yara_matches = [m.rule for m in matches]
        except Exception as exc:
            result.error = f"yara error: {exc}"

    if check_vt and threatintel.available():
        verdict = threatintel.check_hash(result.sha256)
        result.vt_verdict = verdict.verdict
        result.vt_detail = verdict.detail

    return result


def scan_path(path: str, max_files: int = 500) -> list[FileScanResult]:
    """Scan a single file or all files under a directory."""
    if os.path.isfile(path):
        return [scan_file(path)]
    results: list[FileScanResult] = []
    if not os.path.isdir(path):
        return [FileScanResult(file=path, error="path not found")]
    for root, _dirs, files in os.walk(path):
        for name in files:
            results.append(scan_file(os.path.join(root, name)))
            if len(results) >= max_files:
                return results
    return results
