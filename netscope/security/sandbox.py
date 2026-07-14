"""Malware sandboxing (the guide's Cuckoo / WildFire capability).

Two backends, both optional:
  - **Cuckoo Sandbox** — submit a file to a Cuckoo REST server (NETSCOPE_CUCKOO_URL)
    and read back the behavioural score and triggered signatures.
  - **VirusTotal behaviour** — for a file's hash, read VT's aggregated sandbox
    verdicts (no local detonation needed).

Static detection (hash/VT/YARA) lives in yara_scan; this adds *dynamic* behaviour.
NetScope never executes malware itself — detonation happens in Cuckoo/VT.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field

from ..config import settings
from . import threatintel


@dataclass
class SandboxResult:
    file: str = ""
    sha256: str = ""
    verdict: str = "unknown"          # clean | suspicious | malicious | unknown
    score: float = 0.0
    signatures: list[str] = field(default_factory=list)
    source: str = ""                  # cuckoo | virustotal | none
    detail: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


def available() -> bool:
    return bool(settings.cuckoo_url) or threatintel.available()


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Cuckoo
# --------------------------------------------------------------------------- #
def _cuckoo_headers() -> dict:
    return {"Authorization": f"Bearer {settings.cuckoo_token}"} if settings.cuckoo_token else {}


def cuckoo_submit(path: str) -> int | None:
    try:
        import requests

        with open(path, "rb") as fh:
            resp = requests.post(
                settings.cuckoo_url.rstrip("/") + "/tasks/create/file",
                files={"file": (os.path.basename(path), fh)},
                headers=_cuckoo_headers(), timeout=30,
            )
        if resp.status_code in (200, 201):
            return resp.json().get("task_id") or resp.json().get("task_ids", [None])[0]
    except Exception:
        pass
    return None


def parse_cuckoo_report(report: dict) -> tuple[float, list[str]]:
    """Pure parser: (score, signature names) from a Cuckoo report JSON."""
    score = float(report.get("info", {}).get("score", 0.0) or 0.0)
    sigs = [s.get("name", "") for s in report.get("signatures", []) if s.get("name")]
    return score, sigs


def cuckoo_report(task_id: int, wait_s: int = 60) -> dict | None:
    try:
        import requests

        deadline = wait_s
        url = settings.cuckoo_url.rstrip("/") + f"/tasks/report/{task_id}"
        while deadline > 0:
            resp = requests.get(url, headers=_cuckoo_headers(), timeout=20)
            if resp.status_code == 200:
                return resp.json()
            time.sleep(5)
            deadline -= 5
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------- #
# VirusTotal behaviour
# --------------------------------------------------------------------------- #
def parse_vt_verdicts(data: dict) -> tuple[str, list[str]]:
    """Pure parser: (verdict, behaviour tags) from a VT file object."""
    attrs = data.get("data", {}).get("attributes", data.get("attributes", {}))
    verdicts = attrs.get("sandbox_verdicts", {}) or {}
    tags: list[str] = []
    malicious = False
    for v in verdicts.values():
        cat = v.get("category", "")
        if cat == "malicious":
            malicious = True
        tags += v.get("malware_classification", []) or []
    stats = attrs.get("last_analysis_stats", {})
    if not malicious and stats.get("malicious", 0) >= 1:
        malicious = True
    verdict = "malicious" if malicious else ("clean" if verdicts or stats else "unknown")
    return verdict, sorted(set(tags))[:10]


def _vt_behaviour(sha256: str) -> tuple[str, list[str]]:
    if not threatintel.available():
        return "unknown", []
    try:
        import requests

        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": settings.vt_api_key}, timeout=20,
        )
        if resp.status_code == 200:
            return parse_vt_verdicts(resp.json())
    except Exception:
        pass
    return "unknown", []


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def analyze_file(path: str) -> SandboxResult:
    if not os.path.isfile(path):
        return SandboxResult(file=path, detail="file not found")
    result = SandboxResult(file=os.path.basename(path))
    try:
        result.sha256 = _sha256(path)
    except Exception as exc:
        result.detail = f"read error: {exc}"
        return result

    # Prefer VirusTotal behaviour (fast, no local detonation).
    verdict, tags = _vt_behaviour(result.sha256)
    if verdict != "unknown":
        result.verdict, result.signatures, result.source = verdict, tags, "virustotal"

    # Cuckoo dynamic detonation if configured.
    if settings.cuckoo_url:
        task = cuckoo_submit(path)
        if task:
            report = cuckoo_report(task)
            if report:
                score, sigs = parse_cuckoo_report(report)
                result.score = score
                result.signatures = list(dict.fromkeys(result.signatures + sigs))
                result.source = "cuckoo"
                if score >= 5:
                    result.verdict = "malicious"
                elif score >= 2:
                    result.verdict = "suspicious"

    if result.source == "":
        result.detail = "no sandbox configured (set NETSCOPE_CUCKOO_URL or NETSCOPE_VT_API_KEY)"
        result.source = "none"
    return result
