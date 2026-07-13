"""Network discovery: find live hosts on the local subnet.

Strategy (robust, works without admin on Windows):
  1. Detect the local IP and subnet (CIDR).
  2. Concurrent ping sweep to wake hosts and populate the ARP cache.
  3. Parse the OS ARP table (``arp -a``) for IP -> MAC mappings.
  4. Optionally augment with a scapy ARP sweep (faster/complete) when Npcap
     and privileges allow.
  5. Best-effort reverse-DNS hostname resolution.
"""
from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..config import settings

IS_WINDOWS = platform.system().lower().startswith("win")


@dataclass
class Host:
    ip: str
    mac: str = ""
    hostname: str = ""
    responded_ping: bool = False
    ttl: int | None = None
    extras: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Subnet detection
# --------------------------------------------------------------------------- #
def get_local_ip() -> str:
    """Best-effort local IP by opening a UDP socket toward a public address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _netmask_for(local_ip: str) -> str | None:
    """Try to read the interface netmask (Windows: parse ipconfig)."""
    try:
        if IS_WINDOWS:
            out = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=8
            ).stdout
            blocks = re.split(r"\r?\n\r?\n", out)
            for block in blocks:
                if local_ip in block:
                    m = re.search(r"Subnet Mask[ .]*:\s*([\d.]+)", block)
                    if m:
                        return m.group(1)
    except Exception:
        pass
    return None


def detect_subnet() -> str:
    """Return the CIDR of the local network (e.g. ``192.168.1.0/24``)."""
    if settings.subnet:
        return settings.subnet
    local_ip = get_local_ip()
    mask = _netmask_for(local_ip)
    try:
        if mask:
            net = ipaddress.IPv4Network(f"{local_ip}/{mask}", strict=False)
        else:
            net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        # Guard against huge scans on unusual masks.
        if net.num_addresses > 4096:
            net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(net)
    except Exception:
        return f"{local_ip.rsplit('.', 1)[0]}.0/24"


def detect_all_subnets() -> list[str]:
    """Detect every local IPv4 subnet (one per active adapter) as CIDRs."""
    subnets: list[str] = []
    try:
        if IS_WINDOWS:
            out = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=8
            ).stdout
            blocks = re.split(r"\r?\n\r?\n", out)
            for block in blocks:
                ip_m = re.search(r"IPv4 Address[ .]*:\s*([\d.]+)", block)
                mask_m = re.search(r"Subnet Mask[ .]*:\s*([\d.]+)", block)
                if not (ip_m and mask_m):
                    continue
                ip, mask = ip_m.group(1), mask_m.group(1)
                if ip.startswith(("127.", "169.254.")):
                    continue
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    if net.num_addresses > 4096:
                        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                    cidr = str(net)
                    if cidr not in subnets:
                        subnets.append(cidr)
                except Exception:
                    continue
    except Exception:
        pass
    if not subnets:
        subnets = [detect_subnet()]
    return subnets


def get_scan_targets() -> list[str]:
    """Return the list of subnets to scan, based on configuration.

    Priority: explicit NETSCOPE_SUBNETS list > scan_all_local > single subnet.
    """
    if settings.subnets.strip():
        targets = [s.strip() for s in settings.subnets.split(",") if s.strip()]
        if targets:
            return targets
    if settings.scan_all_local:
        return detect_all_subnets()
    return [detect_subnet()]


def get_gateway_ip() -> str:
    """Best-effort default gateway (the router)."""
    try:
        if IS_WINDOWS:
            out = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=8
            ).stdout
            m = re.search(r"Default Gateway[ .]*:\s*([\d.]+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    # Fall back to the conventional .1 of the local /24.
    return get_local_ip().rsplit(".", 1)[0] + ".1"


# --------------------------------------------------------------------------- #
# Ping sweep
# --------------------------------------------------------------------------- #
def _ping(ip: str) -> tuple[bool, int | None]:
    """Ping a single host once. Returns (alive, ttl)."""
    timeout = settings.ping_timeout_ms
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout // 1000)), ip]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout / 1000 + 2
        ).stdout.lower()
    except Exception:
        return False, None
    if "ttl=" not in out:
        return False, None
    ttl = None
    m = re.search(r"ttl=(\d+)", out)
    if m:
        ttl = int(m.group(1))
    return True, ttl


def ping_sweep(cidr: str) -> dict[str, tuple[bool, int | None]]:
    net = ipaddress.IPv4Network(cidr, strict=False)
    hosts = [str(ip) for ip in net.hosts()]
    results: dict[str, tuple[bool, int | None]] = {}
    with ThreadPoolExecutor(max_workers=settings.max_workers) as pool:
        for ip, res in zip(hosts, pool.map(_ping, hosts)):
            results[ip] = res
    return results


# --------------------------------------------------------------------------- #
# ARP table
# --------------------------------------------------------------------------- #
_ARP_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
)


def read_arp_table() -> dict[str, str]:
    """Return {ip: mac} from the OS ARP cache."""
    mapping: dict[str, str] = {}
    try:
        out = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=10
        ).stdout
    except Exception:
        return mapping
    for line in out.splitlines():
        m = re.search(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})",
            line,
        )
        if not m:
            continue
        ip = m.group(1)
        mac = m.group(2).replace("-", ":").upper()
        if mac in {"FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"}:
            continue
        mapping[ip] = mac
    return mapping


def scapy_arp_sweep(cidr: str) -> dict[str, str]:
    """Optional fast ARP sweep via scapy (needs Npcap + privileges)."""
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
    except Exception:
        return {}
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        answered, _ = srp(pkt, timeout=3, verbose=0)
    except Exception:
        return {}
    result: dict[str, str] = {}
    for _, rcv in answered:
        result[rcv.psrc] = rcv.hwsrc.upper()
    return result


# --------------------------------------------------------------------------- #
# Hostname
# --------------------------------------------------------------------------- #
def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def _is_real_host(ip: str) -> bool:
    """Exclude multicast, broadcast, loopback and other non-device addresses."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except Exception:
        return False
    if addr.is_multicast or addr.is_loopback or addr.is_unspecified or addr.is_reserved:
        return False
    if ip.endswith(".255") or ip.endswith(".0"):
        return False
    return True


def discover(cidr: str | None = None) -> list[Host]:
    """Discover live hosts on the subnet and return them with IP/MAC/hostname."""
    cidr = cidr or detect_subnet()

    ping_results = ping_sweep(cidr)
    arp_map = read_arp_table()
    scapy_map = scapy_arp_sweep(cidr)

    # Merge everything we found by IP.
    ips: set[str] = set()
    ips.update(ip for ip, (alive, _) in ping_results.items() if alive)
    ips.update(arp_map.keys())
    ips.update(scapy_map.keys())
    ips = {ip for ip in ips if _is_real_host(ip)}

    hosts: list[Host] = []
    for ip in sorted(ips, key=lambda x: tuple(int(o) for o in x.split("."))):
        alive, ttl = ping_results.get(ip, (False, None))
        mac = scapy_map.get(ip) or arp_map.get(ip, "")
        host = Host(
            ip=ip,
            mac=mac,
            responded_ping=alive,
            ttl=ttl,
            hostname=resolve_hostname(ip),
        )
        hosts.append(host)
    return hosts
