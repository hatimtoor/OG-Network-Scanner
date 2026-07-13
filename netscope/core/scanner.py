"""Full-scan orchestration: discovery + mDNS + ports + identification."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict

from ..config import settings
from . import discovery, identify, mdns, portscan


def run_scan(cidr: str | None = None, do_ports: bool | None = None) -> list[dict]:
    """Run a complete scan across all target subnets and return device dicts."""
    targets = [cidr] if cidr else discovery.get_scan_targets()
    gateway = discovery.get_gateway_ip()
    do_ports = settings.port_scan_enabled if do_ports is None else do_ports

    # Discover hosts across every target subnet, de-duplicated by IP.
    hosts: list[discovery.Host] = []
    seen_ips: set[str] = set()
    for target in targets:
        try:
            for host in discovery.discover(target):
                if host.ip not in seen_ips:
                    seen_ips.add(host.ip)
                    hosts.append(host)
        except Exception:
            continue

    mdns_map = mdns.browse(duration=3.0)

    def enrich(host: discovery.Host) -> dict:
        ports_result = portscan.ScanResult()
        if do_ports:
            try:
                ports_result = portscan.scan(host.ip)
            except Exception:
                ports_result = portscan.ScanResult()

        open_ports = [p.port for p in ports_result.ports]
        services = mdns_map.get(host.ip, [])

        ident = identify.identify(
            mac=host.mac,
            ip=host.ip,
            hostname=host.hostname,
            gateway_ip=gateway,
            open_ports=open_ports,
            ttl=host.ttl,
            mdns_services=services,
            nmap_os=ports_result.os_guess,
        )

        return {
            "mac": host.mac,
            "ip": host.ip,
            "hostname": host.hostname,
            "vendor": ident.vendor,
            "device_type": ident.device_type,
            "os_guess": ident.os_guess,
            "confidence": ident.confidence,
            "reasons": ident.reasons or [],
            "ports": [asdict(p) for p in ports_result.ports],
            "scan_method": ports_result.method,
            "mdns_services": services,
        }

    # Port scans are I/O-bound; run a few hosts concurrently.
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(hosts)))) as pool:
        devices = list(pool.map(enrich, hosts))
    return devices
