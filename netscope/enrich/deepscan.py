"""Deep-scan orchestrator: run all enrichment probes against one device."""
from __future__ import annotations

from ..config import settings
from . import banners, cve, passive, snmp, upnp


def deep_scan(ip: str, mac: str = "", open_ports: list[int] | None = None,
              community: str | None = None, with_cve: bool = True) -> dict:
    """Run UPnP + banners + SNMP + passive lookup + CVE for a single device."""
    open_ports = open_ports or []
    community = community or settings.snmp_community
    details: dict = {}
    hints: list[str] = []

    # UPnP description (exact model / serial / manufacturer)
    try:
        u = upnp.describe_ip(ip)
        if not u.is_empty():
            details["upnp"] = u.to_dict()
            for f in (u.model_name, u.model_number, u.manufacturer):
                if f:
                    hints.append(f)
    except Exception:
        pass

    # Service banners, HTTP headers, TLS certs
    try:
        b = banners.probe_ports(ip, open_ports)
        if b.ports:
            details["ports"] = [p.to_dict() for p in b.ports]
        hints.extend(b.hints)
    except Exception:
        pass

    # SNMP system group
    try:
        s = snmp.get_system_info(ip, community)
        if not s.is_empty():
            details["snmp"] = s.to_dict()
            if s.descr:
                hints.append(s.descr)
    except Exception:
        pass

    # Passive DHCP/LLDP fingerprint (by MAC)
    try:
        p = passive.listener.get(mac)
        if p:
            details["passive"] = p
    except Exception:
        pass

    cves = cve.correlate(hints) if with_cve else []
    return {"details": details, "cves": cves, "hints": hints}
