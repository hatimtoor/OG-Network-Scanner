"""Passive LAN listener: DHCP fingerprinting and LLDP, via scapy/Npcap.

DHCP and LLDP are broadcast/multicast, so every host on the LAN can see them --
no mirror port needed. DHCP option 55 (the parameter-request list) is a strong
OS fingerprint; LLDP frames reveal infrastructure gear (switches, APs, VoIP
phones). Runs quietly in the background and never injects traffic (read-only).
"""
from __future__ import annotations

import threading

# DHCP option-55 signatures -> OS family (heuristic; a small starter set).
_DHCP_SIGNATURES = {
    "1,3,6,15,119,252": "Apple (macOS/iOS)",
    "1,3,6,15,119,95,252,44,46": "Apple (macOS/iOS)",
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252": "Windows",
    "1,15,3,6,44,46,47,31,33,121,249,43": "Windows",
    "1,33,3,6,15,26,28,51,58,59,43": "Android",
    "1,121,33,3,6,15,26,28,51,58,59,43": "Android",
    "1,3,6,12,15,28,42": "Linux",
}


class PassiveListener:
    """Background sniffer maintaining {mac: fingerprint-dict}."""

    def __init__(self) -> None:
        self._sniffer = None
        self._store: dict[str, dict] = {}
        self._domains: dict[str, dict] = {}   # domain -> {count, src, first_seen}
        self._lock = threading.Lock()
        self.active = False

    def start(self) -> bool:
        try:
            from scapy.all import AsyncSniffer  # type: ignore
        except Exception:
            return False
        if self._sniffer is not None:
            return True
        try:
            self._sniffer = AsyncSniffer(
                filter="udp port 67 or udp port 68 or udp port 53 or ether proto 0x88cc",
                prn=self._handle,
                store=False,
            )
            self._sniffer.start()
            self.active = True
            return True
        except Exception:
            self._sniffer = None
            return False

    def stop(self) -> None:
        try:
            if self._sniffer is not None:
                self._sniffer.stop()
        except Exception:
            pass
        self._sniffer = None
        self.active = False

    def get(self, mac: str) -> dict:
        with self._lock:
            return dict(self._store.get((mac or "").upper(), {}))

    def all(self) -> dict[str, dict]:
        with self._lock:
            return dict(self._store)

    # ---- packet handling ---- #
    def _update(self, mac: str, data: dict) -> None:
        if not mac:
            return
        key = mac.upper()
        with self._lock:
            entry = self._store.setdefault(key, {})
            for k, v in data.items():
                if v:
                    entry[k] = v

    def _handle(self, pkt) -> None:
        try:
            self._handle_dhcp(pkt)
            self._handle_lldp(pkt)
            self._handle_dns(pkt)
        except Exception:
            pass

    def _handle_dns(self, pkt) -> None:
        try:
            from scapy.layers.dns import DNSQR  # type: ignore
            from scapy.layers.inet import IP  # type: ignore
        except Exception:
            return
        if not pkt.haslayer(DNSQR):
            return
        try:
            qname = pkt[DNSQR].qname
            domain = (qname.decode("utf-8", "ignore") if isinstance(qname, bytes) else str(qname)).strip(".")
        except Exception:
            return
        if not domain or domain.endswith((".local", ".arpa", ".lan")):
            return
        src = pkt[IP].src if pkt.haslayer(IP) else ""
        with self._lock:
            entry = self._domains.setdefault(domain, {"count": 0, "src": src})
            entry["count"] += 1

    def recent_domains(self) -> dict[str, dict]:
        with self._lock:
            return dict(self._domains)

    def clear_domains(self) -> None:
        with self._lock:
            self._domains.clear()

    def _handle_dhcp(self, pkt) -> None:
        try:
            from scapy.layers.dhcp import DHCP  # type: ignore
            from scapy.layers.l2 import Ether  # type: ignore
        except Exception:
            return
        if not pkt.haslayer(DHCP):
            return
        mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
        prl = ""
        vendor = ""
        for opt in pkt[DHCP].options:
            if not isinstance(opt, tuple):
                continue
            if opt[0] == "param_req_list":
                nums = opt[1] if isinstance(opt[1], (list, tuple)) else [opt[1]]
                prl = ",".join(str(int(n)) for n in nums)
            elif opt[0] == "vendor_class_id":
                vendor = opt[1].decode("utf-8", "ignore") if isinstance(opt[1], bytes) else str(opt[1])
        if prl:
            self._update(mac, {
                "dhcp_fingerprint": prl,
                "dhcp_os": _DHCP_SIGNATURES.get(prl, ""),
                "dhcp_vendor_class": vendor,
            })

    def _handle_lldp(self, pkt) -> None:
        try:
            from scapy.contrib.lldp import LLDPDUSystemName, LLDPDUSystemDescription  # type: ignore
            from scapy.layers.l2 import Ether  # type: ignore
        except Exception:
            return
        mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
        data = {}
        if pkt.haslayer(LLDPDUSystemName):
            try:
                data["lldp_name"] = pkt[LLDPDUSystemName].system_name.decode("utf-8", "ignore")
            except Exception:
                pass
        if pkt.haslayer(LLDPDUSystemDescription):
            try:
                data["lldp_descr"] = pkt[LLDPDUSystemDescription].description.decode("utf-8", "ignore")
            except Exception:
                pass
        if data:
            self._update(mac, data)


# Module-level singleton used by the monitor and deep scan.
listener = PassiveListener()


def os_from_fingerprint(prl: str) -> str:
    return _DHCP_SIGNATURES.get(prl, "")
