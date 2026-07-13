"""Vulnerability correlation via the NVD (National Vulnerability Database) API.

Given software/version hints discovered during a deep scan (e.g. "OpenSSH 8.9",
"nginx 1.24"), this queries NVD for known CVEs and returns the most severe ones.
An NVD API key (NETSCOPE_NVD_API_KEY) raises the rate limit but isn't required.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..config import settings

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_cache: dict[str, list["Cve"]] = {}

# Only bother correlating hints that look like "<product> <version>".
_VERSIONED = re.compile(r"[A-Za-z][A-Za-z0-9+.\- ]*\d")


@dataclass
class Cve:
    id: str
    severity: str = "UNKNOWN"
    score: float = 0.0
    summary: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


def _normalize(hint: str) -> str:
    # "OpenSSH_8.9p1 Ubuntu" -> "OpenSSH 8.9"; "nginx/1.24.0" -> "nginx 1.24.0"
    text = re.sub(r"[/_]", " ", hint)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:60]


def _severity(metrics: dict) -> tuple[str, float]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            d = metrics[key][0]["cvssData"]
            return d.get("baseSeverity", "UNKNOWN"), float(d.get("baseScore", 0.0))
    if metrics.get("cvssMetricV2"):
        d = metrics["cvssMetricV2"][0]
        return d.get("baseSeverity", "UNKNOWN"), float(d["cvssData"].get("baseScore", 0.0))
    return "UNKNOWN", 0.0


def search_cves(hint: str, limit: int = 5) -> list[Cve]:
    term = _normalize(hint)
    if not term or not _VERSIONED.search(term):
        return []
    if term in _cache:
        return _cache[term]

    try:
        import requests

        headers = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
        resp = requests.get(
            _NVD_URL,
            params={"keywordSearch": term, "resultsPerPage": 20},
            headers=headers,
            timeout=20,
        )
        if resp.status_code != 200:
            return []
        vulns = resp.json().get("vulnerabilities", [])
    except Exception:
        return []

    cves: list[Cve] = []
    for v in vulns:
        c = v.get("cve", {})
        cid = c.get("id", "")
        summary = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                summary = d.get("value", "")[:200]
                break
        sev, score = _severity(c.get("metrics", {}))
        cves.append(Cve(id=cid, severity=sev, score=score, summary=summary))

    cves.sort(key=lambda x: x.score, reverse=True)
    top = cves[:limit]
    _cache[term] = top
    return top


def correlate(hints: list[str], max_hints: int = 4, per_hint: int = 3) -> list[dict]:
    """Correlate several product hints and return a de-duplicated CVE list."""
    seen: set[str] = set()
    out: list[dict] = []
    for hint in list(dict.fromkeys(hints))[:max_hints]:
        for cve in search_cves(hint, limit=per_hint):
            if cve.id and cve.id not in seen:
                seen.add(cve.id)
                d = cve.to_dict()
                d["source_hint"] = _normalize(hint)
                out.append(d)
    out.sort(key=lambda x: x["score"], reverse=True)
    return out
