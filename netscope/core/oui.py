"""MAC address vendor (OUI) lookup.

Uses the Wireshark "manuf" database (downloaded and cached locally) for accurate
offline vendor lookups, with a small built-in fallback for immediate results
before the cache is populated. Also detects locally-administered / randomized
MAC addresses, which modern phones use for privacy.
"""
from __future__ import annotations

import os
import threading
from functools import lru_cache
from pathlib import Path

_MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
_CACHE_DIR = Path.home() / ".cache" / "netscope"
_CACHE_FILE = _CACHE_DIR / "manuf.txt"

# prefix-hex -> vendor name, split by mask width (24/28/36 bits => 6/7/9 nibbles)
_oui24: dict[str, str] = {}
_oui28: dict[str, str] = {}
_oui36: dict[str, str] = {}
_loaded = False
_download_started = False

# Minimal fallback so we still name common vendors before the DB is cached.
_FALLBACK_OUI = {
    "FCFBFB": "Cisco", "3C5AB4": "Google", "44650D": "Amazon", "F0D2F1": "Amazon",
    "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi Trading",
    "001CB3": "Apple", "A483E7": "Apple", "F01898": "Apple", "50C7BF": "TP-Link",
    "C05627": "Belkin", "00095B": "Netgear", "0024B2": "Netgear",
}


def is_randomized_mac(mac: str) -> bool:
    """Return True if the MAC is locally administered (randomized/private).

    Bit 0x02 of the first octet marks a locally-administered address — the
    signature of iOS/Android/Windows MAC randomization.
    """
    if not mac or ":" not in mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
    except ValueError:
        return False
    return bool(first_octet & 0b10)


def _norm(mac: str) -> str:
    return mac.upper().replace(":", "").replace("-", "").replace(".", "")


def _parse_manuf(text: str) -> None:
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        prefix = parts[0].strip()
        vendor = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
        mask = 24
        if "/" in prefix:
            prefix, _, m = prefix.partition("/")
            try:
                mask = int(m)
            except ValueError:
                mask = 24
        key = _norm(prefix)
        if mask >= 36:
            _oui36[key[:9]] = vendor
        elif mask >= 28:
            _oui28[key[:7]] = vendor
        else:
            _oui24[key[:6]] = vendor


def _load_cache() -> bool:
    global _loaded
    try:
        if _CACHE_FILE.exists() and _CACHE_FILE.stat().st_size > 1000:
            _parse_manuf(_CACHE_FILE.read_text(encoding="utf-8", errors="ignore"))
            _loaded = True
            return True
    except Exception:
        pass
    return False


def _download() -> None:
    global _download_started
    if _download_started:
        return
    _download_started = True

    def _worker() -> None:
        global _loaded
        try:
            import requests

            resp = requests.get(_MANUF_URL, timeout=30)
            if resp.status_code == 200 and len(resp.content) > 1000:
                _CACHE_DIR.mkdir(parents=True, exist_ok=True)
                _CACHE_FILE.write_text(resp.text, encoding="utf-8")
                _parse_manuf(resp.text)
                _loaded = True
                lookup_vendor.cache_clear()
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True).start()


@lru_cache(maxsize=8192)
def lookup_vendor(mac: str) -> str:
    """Return the manufacturer for a MAC address, or a descriptive fallback."""
    if not mac:
        return "Unknown"
    if is_randomized_mac(mac):
        return "Private (randomized MAC)"

    if not _loaded:
        if not _load_cache():
            _download()  # populate cache in background for next time

    key = _norm(mac)
    if _loaded:
        vendor = _oui36.get(key[:9]) or _oui28.get(key[:7]) or _oui24.get(key[:6])
        if vendor:
            return vendor

    return _FALLBACK_OUI.get(key[:6], "Unknown")


# Try to load any existing cache at import time (non-blocking, no network).
_load_cache()
