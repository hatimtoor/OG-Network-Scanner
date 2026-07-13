"""Lightweight mDNS/Bonjour discovery.

Browses common service types for a few seconds and maps IP addresses to the
service types they advertise. This helps identify device type even when the MAC
is randomized. Fails silently (returns {}) if zeroconf is unavailable.
"""
from __future__ import annotations

import socket
import time

_SERVICE_TYPES = [
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_ssh._tcp.local.",
    "_workstation._tcp.local.",
    "_hap._tcp.local.",
    "_sonos._tcp.local.",
    "_apple-mobdev2._tcp.local.",
    "_http._tcp.local.",
]


def browse(duration: float = 3.0) -> dict[str, list[str]]:
    """Return {ip: [service_type, ...]} discovered via mDNS within ``duration``."""
    try:
        from zeroconf import ServiceBrowser, Zeroconf  # type: ignore
    except Exception:
        return {}

    found: dict[str, list[str]] = {}

    class _Listener:
        def add_service(self, zc, type_, name):  # noqa: N802 (zeroconf API)
            try:
                info = zc.get_service_info(type_, name, timeout=1500)
            except Exception:
                return
            if not info:
                return
            for addr in info.parsed_addresses():
                if ":" in addr:  # skip IPv6 for the v1 dashboard
                    continue
                found.setdefault(addr, [])
                if type_ not in found[addr]:
                    found[addr].append(type_)

        def update_service(self, zc, type_, name):  # noqa: N802
            self.add_service(zc, type_, name)

        def remove_service(self, zc, type_, name):  # noqa: N802
            pass

    try:
        zc = Zeroconf()
    except Exception:
        return {}
    listener = _Listener()
    browsers = []
    try:
        for st in _SERVICE_TYPES:
            try:
                browsers.append(ServiceBrowser(zc, st, listener))
            except Exception:
                continue
        time.sleep(duration)
    finally:
        try:
            zc.close()
        except Exception:
            pass
    return found
