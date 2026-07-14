"""Deep-scan orchestrator: run every enrichment probe against one device.

Unlike the light per-scan enrichment, a deep scan does *active* work so it
always returns something useful even for a plain phone or laptop that exposes no
UPnP/SNMP: it runs its own service scan, resolves reverse-DNS and NetBIOS names,
measures latency/TTL, resolves the MAC vendor, flags randomized MACs, and folds
everything into a fresh identity guess.
"""
from __future__ import annotations

import platform
import re
import socket
import subprocess

from ..config import settings
from ..core import identify, oui, portscan
from . import banners, cve, passive, snmp, upnp

_NB_NAME_RE = re.compile(r"^\s*([\w\-\.\$]+)\s*<([0-9A-Fa-f]{2})>\s+UNIQUE")
_PING_TIME_RE = re.compile(r"time[=<]\s*([\d\.]+)\s*ms", re.I)
_PING_TTL_RE = re.compile(r"ttl[=]\s*(\d+)", re.I)


def _reverse_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(2.0)
        host, _, _ = socket.gethostbyaddr(ip)
        return host or ""
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)


def _netbios_name(ip: str) -> str:
    """Windows NetBIOS name via ``nbtstat -A`` (returns '' on non-Windows/failure)."""
    if platform.system() != "Windows":
        return ""
    try:
        out = subprocess.run(
            ["nbtstat", "-A", ip], capture_output=True, text=True, timeout=4,
        ).stdout
    except Exception:
        return ""
    for line in out.splitlines():
        m = _NB_NAME_RE.match(line)
        # <00> UNIQUE is the workstation/computer name; skip messenger names.
        if m and m.group(2).lower() == "00":
            return m.group(1).strip()
    return ""


def _ping(ip: str) -> tuple[float | None, int | None]:
    """Return (rtt_ms, ttl) from a single ping, or (None, None)."""
    is_win = platform.system() == "Windows"
    cmd = ["ping", "-n", "1", "-w", "1500", ip] if is_win else ["ping", "-c", "1", "-W", "2", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None, None
    rtt = float(m.group(1)) if (m := _PING_TIME_RE.search(out)) else None
    ttl = int(m.group(1)) if (m := _PING_TTL_RE.search(out)) else None
    return rtt, ttl


def deep_scan(ip: str, mac: str = "", open_ports: list[int] | None = None,
              community: str | None = None, with_cve: bool = True) -> dict:
    """Run a full active enrichment sweep for a single device."""
    community = community or settings.snmp_community
    details: dict = {}
    hints: list[str] = []

    # --- Always-available signals (work even with no open ports) ---
    rdns = _reverse_dns(ip)
    if rdns:
        details["reverse_dns"] = rdns
        hints.append(rdns)

    netbios = _netbios_name(ip)
    if netbios:
        details["netbios_name"] = netbios

    rtt, ttl = _ping(ip)
    if rtt is not None:
        details["latency_ms"] = rtt
    if ttl is not None:
        details["ttl"] = ttl

    if mac:
        details["vendor"] = oui.lookup_vendor(mac)
        details["randomized_mac"] = oui.is_randomized_mac(mac)

    # --- Active service/version scan (do our own; don't rely on cached ports) ---
    scan_res = portscan.scan(ip)
    scanned_ports = [p.port for p in scan_res.ports]
    if scan_res.ports:
        details["services"] = [
            {"port": p.port, "service": p.service, "product": p.product, "risky": p.risky}
            for p in scan_res.ports
        ]
        for p in scan_res.ports:
            if p.product:
                hints.append(p.product)
    if scan_res.os_guess:
        details["nmap_os"] = scan_res.os_guess
    probe_ports = scanned_ports or (open_ports or [])

    # --- UPnP description (exact model / serial / manufacturer) ---
    try:
        u = upnp.describe_ip(ip)
        if not u.is_empty():
            details["upnp"] = u.to_dict()
            for f in (u.model_name, u.model_number, u.manufacturer):
                if f:
                    hints.append(f)
    except Exception:
        pass

    # --- Service banners, HTTP headers, TLS certs on the live ports ---
    try:
        b = banners.probe_ports(ip, probe_ports)
        if b.ports:
            details["banners"] = [p.to_dict() for p in b.ports]
        hints.extend(b.hints)
    except Exception:
        pass

    # --- SNMP system group ---
    try:
        s = snmp.get_system_info(ip, community)
        if not s.is_empty():
            details["snmp"] = s.to_dict()
            if s.descr:
                hints.append(s.descr)
    except Exception:
        pass

    # --- Passive DHCP/LLDP fingerprint (by MAC) ---
    try:
        p = passive.listener.get(mac)
        if p:
            details["passive"] = p
    except Exception:
        pass

    # --- Fold every signal into a fresh identity guess ---
    dhcp_os = details.get("passive", {}).get("dhcp_os", "") if isinstance(details.get("passive"), dict) else ""
    ident = identify.identify(
        mac=mac, ip=ip,
        hostname=rdns or netbios,
        open_ports=probe_ports, ttl=ttl,
        nmap_os=scan_res.os_guess or dhcp_os,
    )
    details["identity"] = {
        "device_type": ident.device_type,
        "os_guess": ident.os_guess,
        "vendor": ident.vendor,
        "confidence": ident.confidence,
        "reasons": ident.reasons or [],
    }

    cves = cve.correlate(hints) if with_cve else []
    return {"details": details, "cves": cves, "hints": hints}
