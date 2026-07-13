"""Threat intelligence via VirusTotal.

Checks IPs, domains, and file hashes against VirusTotal's aggregated engines.
Requires a free API key (NETSCOPE_VT_API_KEY); without one, lookups return an
``unknown`` verdict rather than failing. Results are cached in memory to respect
the free tier's rate limits.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ..config import settings

_VT_BASE = "https://www.virustotal.com/api/v3"
_cache: dict[str, "ThreatVerdict"] = {}


@dataclass
class ThreatVerdict:
    indicator: str
    kind: str            # "ip" | "domain" | "file"
    verdict: str         # "clean" | "suspicious" | "malicious" | "unknown"
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    reputation: int = 0
    detail: str = ""

    def to_dict(self) -> dict:
        return self.__dict__


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def available() -> bool:
    return bool(settings.vt_api_key)


def _verdict_from_stats(indicator: str, kind: str, stats: dict, reputation: int) -> ThreatVerdict:
    mal = int(stats.get("malicious", 0))
    sus = int(stats.get("suspicious", 0))
    harm = int(stats.get("harmless", 0))
    if mal >= 1:
        v = "malicious"
    elif sus >= 2:
        v = "suspicious"
    elif harm > 0 or reputation >= 0:
        v = "clean"
    else:
        v = "unknown"
    detail = f"{mal} malicious / {sus} suspicious / {harm} harmless engines"
    return ThreatVerdict(indicator, kind, v, mal, sus, harm, reputation, detail)


def _lookup(kind: str, path: str, indicator: str) -> ThreatVerdict:
    key = f"{kind}:{indicator}"
    if key in _cache:
        return _cache[key]

    if kind == "ip" and _is_private_ip(indicator):
        verdict = ThreatVerdict(indicator, kind, "clean", detail="private/LAN address")
        _cache[key] = verdict
        return verdict

    if not settings.vt_api_key:
        return ThreatVerdict(indicator, kind, "unknown", detail="no VirusTotal API key configured")

    try:
        import requests

        resp = requests.get(
            f"{_VT_BASE}/{path}/{indicator}",
            headers={"x-apikey": settings.vt_api_key},
            timeout=15,
        )
        if resp.status_code == 404:
            verdict = ThreatVerdict(indicator, kind, "unknown", detail="not found in VirusTotal")
            _cache[key] = verdict
            return verdict
        if resp.status_code != 200:
            return ThreatVerdict(indicator, kind, "unknown", detail=f"VT HTTP {resp.status_code}")
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        reputation = int(attrs.get("reputation", 0))
        verdict = _verdict_from_stats(indicator, kind, stats, reputation)
        _cache[key] = verdict
        return verdict
    except Exception as exc:
        return ThreatVerdict(indicator, kind, "unknown", detail=f"lookup error: {exc}")


def check_ip(ip: str) -> ThreatVerdict:
    return _lookup("ip", "ip_addresses", ip)


def check_domain(domain: str) -> ThreatVerdict:
    return _lookup("domain", "domains", domain)


def check_hash(file_hash: str) -> ThreatVerdict:
    return _lookup("file", "files", file_hash.lower())
