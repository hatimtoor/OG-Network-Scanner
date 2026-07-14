"""Threat-intelligence feeds (blocklists).

Fetches public IP/domain blocklists, caches them, and matches indicators against
live traffic (flows) and DNS. A hit raises a critical alert. Feeds are plain-text
(one indicator per line, '#' comments) — the default set is abuse.ch Feodo Tracker
and the aggregated ipsum list. Configure with NETSCOPE_FEED_URLS.
"""
from __future__ import annotations

import ipaddress
import json
import re
import threading
from pathlib import Path

from ..config import settings

_CACHE = Path(settings.db_path).resolve().parent / "threat_feeds.json"
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_ips: set[str] = set()
_domains: set[str] = set()
_hashes: set[str] = set()
_lock = threading.Lock()
_last_refresh: str = ""


def _feed_list() -> list[str]:
    return [u.strip() for u in settings.feed_urls.split(",") if u.strip()]


def parse_feed(text: str) -> tuple[set[str], set[str]]:
    """Pure parser: return (ip_indicators, domain_indicators) from feed text."""
    ips: set[str] = set()
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        token = line.split()[0].strip()          # ipsum is "ip<TAB>count"
        token = token.split(",")[0].strip()
        if _IPV4.match(token):
            try:
                ipaddress.ip_address(token)
                ips.add(token)
            except ValueError:
                pass
        elif "." in token and re.match(r"^[a-zA-Z0-9.\-]+$", token):
            domains.add(token.lower().strip("."))
    return ips, domains


_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")


def parse_misp(data: dict) -> tuple[set[str], set[str], set[str]]:
    """Parse a MISP restSearch response into (ips, domains, hashes)."""
    ips: set[str] = set()
    domains: set[str] = set()
    hashes: set[str] = set()
    # Attribute list may sit at top level or under 'response'.
    attrs = data.get("Attribute") or data.get("response", {}).get("Attribute") or []
    for a in attrs:
        t = a.get("type", "")
        v = (a.get("value", "") or "").strip()
        if not v:
            continue
        if t in ("ip-dst", "ip-src", "ip"):
            if _IPV4.match(v):
                ips.add(v)
        elif t in ("domain", "hostname"):
            domains.add(v.lower().strip("."))
        elif t in ("md5", "sha1", "sha256") and _HASH_RE.match(v):
            hashes.add(v.lower())
    return ips, domains, hashes


def parse_stix(data: dict) -> tuple[set[str], set[str], set[str]]:
    """Parse a STIX 2.x bundle's indicator patterns into (ips, domains, hashes)."""
    ips: set[str] = set()
    domains: set[str] = set()
    hashes: set[str] = set()
    for obj in data.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        for m in re.finditer(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern):
            if _IPV4.match(m.group(1)):
                ips.add(m.group(1))
        for m in re.finditer(r"domain-name:value\s*=\s*'([^']+)'", pattern):
            domains.add(m.group(1).lower().strip("."))
        for m in re.finditer(r"file:hashes\.'?(?:MD5|SHA-?1|SHA-?256)'?\s*=\s*'([^']+)'", pattern):
            if _HASH_RE.match(m.group(1)):
                hashes.add(m.group(1).lower())
    return ips, domains, hashes


def _fetch_misp() -> tuple[set[str], set[str], set[str]]:
    if not (settings.misp_url and settings.misp_key):
        return set(), set(), set()
    try:
        import requests

        url = settings.misp_url.rstrip("/") + "/attributes/restSearch"
        resp = requests.post(
            url,
            headers={"Authorization": settings.misp_key, "Accept": "application/json",
                     "Content-Type": "application/json"},
            json={"returnFormat": "json",
                  "type": ["ip-dst", "ip-src", "domain", "hostname", "md5", "sha256"]},
            timeout=30,
        )
        if resp.status_code == 200:
            return parse_misp(resp.json())
    except Exception:
        pass
    return set(), set(), set()


def _fetch_stix() -> tuple[set[str], set[str], set[str]]:
    if not settings.stix_url:
        return set(), set(), set()
    try:
        import requests

        resp = requests.get(settings.stix_url, timeout=30)
        if resp.status_code == 200:
            return parse_stix(resp.json())
    except Exception:
        pass
    return set(), set(), set()


def check_hash(file_hash: str) -> bool:
    with _lock:
        return (file_hash or "").lower() in _hashes


def load_cache() -> None:
    global _last_refresh
    try:
        data = json.loads(_CACHE.read_text(encoding="utf-8"))
        with _lock:
            _ips.update(data.get("ips", []))
            _domains.update(data.get("domains", []))
            _hashes.update(data.get("hashes", []))
            _last_refresh = data.get("last_refresh", "")
    except Exception:
        pass


def refresh() -> dict:
    """Fetch all feeds and rebuild the indicator sets. Returns a summary."""
    import requests
    from datetime import datetime, timezone

    new_ips: set[str] = set()
    new_domains: set[str] = set()
    new_hashes: set[str] = set()
    ok_feeds = 0
    for url in _feed_list():
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                fi, fd = parse_feed(resp.text)
                new_ips |= fi
                new_domains |= fd
                ok_feeds += 1
        except Exception:
            continue

    # MISP + STIX/TAXII structured feeds (bring hash IOCs too).
    for fetch in (_fetch_misp, _fetch_stix):
        mi, md, mh = fetch()
        if mi or md or mh:
            new_ips |= mi; new_domains |= md; new_hashes |= mh; ok_feeds += 1

    global _last_refresh
    with _lock:
        if new_ips or new_domains or new_hashes:
            _ips.clear(); _ips.update(new_ips)
            _domains.clear(); _domains.update(new_domains)
            _hashes.clear(); _hashes.update(new_hashes)
        _last_refresh = datetime.now(timezone.utc).isoformat()
        snapshot = {"ips": list(_ips), "domains": list(_domains),
                    "hashes": list(_hashes), "last_refresh": _last_refresh}
    try:
        _CACHE.write_text(json.dumps(snapshot), encoding="utf-8")
    except Exception:
        pass
    return {"feeds": ok_feeds, "ips": len(_ips), "domains": len(_domains),
            "hashes": len(_hashes), "last_refresh": _last_refresh}


def check_ip(ip: str) -> bool:
    with _lock:
        return ip in _ips


def check_domain(domain: str) -> bool:
    d = (domain or "").lower().strip(".")
    with _lock:
        if d in _domains:
            return True
        # match parent domains too (sub.evil.com hits evil.com)
        parts = d.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in _domains:
                return True
    return False


def status() -> dict:
    with _lock:
        return {
            "enabled": settings.feeds_enabled,
            "feeds": len(_feed_list()),
            "misp": bool(settings.misp_url and settings.misp_key),
            "stix": bool(settings.stix_url),
            "ip_indicators": len(_ips),
            "domain_indicators": len(_domains),
            "hash_indicators": len(_hashes),
            "last_refresh": _last_refresh,
        }


def available() -> bool:
    with _lock:
        return bool(_ips or _domains)
