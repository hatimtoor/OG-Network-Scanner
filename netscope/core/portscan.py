"""Port and service scanning.

Uses Nmap for service/version + OS detection when it is installed, and always
falls back to a fast concurrent TCP-connect scan (pure Python, no privileges).
"""
from __future__ import annotations

import shutil
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..config import DEFAULT_PORTS, RISKY_PORTS, settings

# Well-known service names for the ports we probe (used by the socket scanner).
_SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 139: "netbios", 143: "imap", 443: "https", 445: "smb",
    515: "printer", 631: "ipp", 993: "imaps", 995: "pop3s", 1723: "pptp",
    1883: "mqtt", 1900: "upnp", 3306: "mysql", 3389: "rdp", 5000: "upnp/http",
    5353: "mdns", 5900: "vnc", 8000: "http-alt", 8009: "chromecast",
    8080: "http-proxy", 8443: "https-alt", 8883: "mqtt-tls", 9100: "printer-raw",
    32400: "plex", 49152: "upnp", 62078: "iphone-sync",
}


@dataclass
class PortResult:
    port: int
    service: str = ""
    product: str = ""
    risky: str = ""  # non-empty description if the open port is risky


@dataclass
class ScanResult:
    ports: list[PortResult] = field(default_factory=list)
    os_guess: str = ""
    method: str = "socket"  # "nmap" or "socket"


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _check_port(ip: str, port: int, timeout: float = 0.6) -> int | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                return port
        except Exception:
            return None
    return None


def socket_scan(ip: str, ports: list[int] | None = None) -> ScanResult:
    ports = ports or DEFAULT_PORTS
    result = ScanResult(method="socket")
    with ThreadPoolExecutor(max_workers=min(64, len(ports))) as pool:
        found = [p for p in pool.map(lambda pt: _check_port(ip, pt), ports) if p]
    for port in sorted(found):
        result.ports.append(
            PortResult(
                port=port,
                service=_SERVICE_NAMES.get(port, ""),
                risky=RISKY_PORTS.get(port, ""),
            )
        )
    return result


def nmap_scan(ip: str) -> ScanResult | None:
    """Service + OS detection via python-nmap. Returns None if unavailable."""
    try:
        import nmap  # type: ignore
    except Exception:
        return None
    if not nmap_available():
        return None
    try:
        scanner = nmap.PortScanner()
        # -sV service/version detection; -T4 fast timing; bounded per-host so a
        # single slow host can't stall the whole scan. OS detection (-O) is
        # intentionally omitted: it needs admin and is slow — TTL gives us an OS
        # hint for free. Enable deep OS detection with NETSCOPE_NMAP_OS=true.
        args = "-sV -T4 --top-ports 50 --host-timeout 20s"
        if settings.nmap_os_detection:
            args += " -O"
        scanner.scan(ip, arguments=args)
    except Exception:
        return None

    if ip not in scanner.all_hosts():
        return ScanResult(method="nmap")

    result = ScanResult(method="nmap")
    host_data = scanner[ip]
    for proto in host_data.all_protocols():
        for port in sorted(host_data[proto].keys()):
            info = host_data[proto][port]
            if info.get("state") != "open":
                continue
            product = " ".join(
                x for x in [info.get("product", ""), info.get("version", "")] if x
            ).strip()
            result.ports.append(
                PortResult(
                    port=port,
                    service=info.get("name", "") or _SERVICE_NAMES.get(port, ""),
                    product=product,
                    risky=RISKY_PORTS.get(port, ""),
                )
            )
    # OS guess
    try:
        matches = host_data.get("osmatch", [])
        if matches:
            result.os_guess = matches[0].get("name", "")
    except Exception:
        pass
    return result


def scan(ip: str) -> ScanResult:
    """Scan a host, preferring Nmap when enabled/available."""
    if settings.use_nmap and settings.port_scan_enabled:
        res = nmap_scan(ip)
        if res is not None and (res.ports or res.os_guess):
            return res
    if settings.port_scan_enabled:
        return socket_scan(ip)
    return ScanResult(method="disabled")
