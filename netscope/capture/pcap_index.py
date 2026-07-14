"""PCAP indexing (mini-Arkime).

Parses a captured .pcap/.pcapng into per-packet metadata (time, src/dst IP,
ports, protocol, length) and stores it in the DuckDB analytics store so packets
are searchable by IP / port / protocol — without loading the whole capture into
Wireshark. Offline: reads files, never touches the network.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from ..db import analytics


def index_file(path: str, max_packets: int = 500_000) -> dict:
    """Parse a PCAP and index its packets. Returns {indexed, file} or {error}."""
    if not os.path.isfile(path):
        return {"error": "file not found"}
    name = os.path.basename(path)
    if name in analytics.indexed_pcap_files():
        return {"indexed": 0, "file": name, "note": "already indexed"}

    try:
        from scapy.all import PcapReader  # type: ignore
        from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    except Exception:
        return {"error": "scapy not available"}

    rows = []
    n = 0
    try:
        with PcapReader(path) as reader:
            for pkt in reader:
                n += 1
                if n > max_packets:
                    break
                if not pkt.haslayer(IP):
                    continue
                ip = pkt[IP]
                sport = dport = 0
                proto = "OTHER"
                if pkt.haslayer(TCP):
                    proto = "TCP"; sport = int(pkt[TCP].sport); dport = int(pkt[TCP].dport)
                elif pkt.haslayer(UDP):
                    proto = "UDP"; sport = int(pkt[UDP].sport); dport = int(pkt[UDP].dport)
                elif ip.proto == 1:
                    proto = "ICMP"
                try:
                    ts = datetime.fromtimestamp(float(pkt.time), timezone.utc).replace(tzinfo=None)
                except Exception:
                    ts = None
                rows.append((ts, ip.src, ip.dst, sport, dport, proto, len(pkt), name, n))
                if len(rows) >= 5000:
                    analytics.record_packets(rows)
                    rows = []
    except Exception as exc:
        if rows:
            analytics.record_packets(rows)
        return {"error": f"parse error: {exc}", "indexed": n, "file": name}

    if rows:
        analytics.record_packets(rows)
    return {"indexed": n, "file": name}
