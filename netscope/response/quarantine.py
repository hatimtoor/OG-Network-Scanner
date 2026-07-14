"""Device quarantine (active response, R15).

Two reversible methods, both requiring explicit user action and fully audited:

  - ``openwrt``: SSH to an OpenWrt router and add a firewall DROP rule for the
    device's MAC (clean, router-enforced). Reverses by deleting the rule.
  - ``arp``: layer-2 isolation from this host via ARP spoofing (router-agnostic
    fallback). More invasive; runs a background thread that must be stopped to
    restore the device.

State is persisted so quarantines survive restarts and can always be undone.
NOTHING here runs automatically — the API layer invokes it on explicit request.
"""
from __future__ import annotations

import json
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

from ..config import settings

_STATE = Path(settings.db_path).resolve().parent / "quarantine_state.json"
_arp_threads: dict[str, threading.Event] = {}
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load() -> dict:
    try:
        return json.loads(_STATE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(data: dict) -> None:
    try:
        _STATE.write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass


def list_quarantined() -> list[dict]:
    return list(_load().values())


# --------------------------------------------------------------------------- #
# OpenWrt firewall method
# --------------------------------------------------------------------------- #
def _openwrt_cmd(mac: str, add: bool) -> str:
    """Build the iptables command to DROP (or restore) a MAC on the router."""
    action = "-I" if add else "-D"
    return f"iptables {action} FORWARD -m mac --mac-source {mac} -j DROP"


def _run_router(router: str, user: str, command: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
             f"{user}@{router}", command],
            capture_output=True, text=True, timeout=30,
        )
        return proc.returncode == 0, (proc.stderr or proc.stdout).strip()
    except Exception as exc:
        return False, str(exc)


# --------------------------------------------------------------------------- #
# ARP isolation method
# --------------------------------------------------------------------------- #
def _arp_isolate_loop(target_ip: str, target_mac: str, gateway_ip: str, stop: threading.Event) -> None:
    try:
        from scapy.all import ARP, Ether, get_if_hwaddr, conf, sendp  # type: ignore
        our_mac = get_if_hwaddr(conf.iface)
    except Exception:
        return
    # Poison the target so it sends gateway-bound traffic to us (we don't forward).
    pkt = Ether(dst=target_mac) / ARP(op=2, psrc=gateway_ip, hwsrc=our_mac, pdst=target_ip, hwdst=target_mac)
    while not stop.is_set():
        try:
            sendp(pkt, verbose=0)
        except Exception:
            break
        stop.wait(2.0)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def quarantine(ip: str, mac: str, method: str = "arp",
               router: str = "", user: str = "root", gateway_ip: str = "",
               duration_minutes: int = 0) -> dict:
    key = (mac or ip).upper()
    record = {"ip": ip, "mac": mac, "method": method, "since": _now(), "key": key,
              "duration_minutes": duration_minutes}

    if method == "openwrt":
        if not (router and mac):
            return {"ok": False, "error": "openwrt method needs router IP and device MAC"}
        ok, detail = _run_router(router, user, _openwrt_cmd(mac, add=True))
        record["router"] = router
        record["detail"] = detail
        if not ok:
            return {"ok": False, "error": f"router command failed: {detail}"}
    elif method == "arp":
        if not (ip and gateway_ip and mac):
            return {"ok": False, "error": "arp method needs device ip+mac and gateway ip"}
        stop = threading.Event()
        t = threading.Thread(target=_arp_isolate_loop, args=(ip, mac, gateway_ip, stop), daemon=True)
        with _lock:
            _arp_threads[key] = stop
        t.start()
    else:
        return {"ok": False, "error": f"unknown method {method}"}

    state = _load(); state[key] = record; _save(state)

    # Timed control ("pause for N minutes") — auto-release later.
    if duration_minutes and duration_minutes > 0:
        threading.Timer(duration_minutes * 60, lambda: release(key, user)).start()

    return {"ok": True, "quarantined": record}


def release(ip_or_mac: str, user: str = "root") -> dict:
    key = (ip_or_mac or "").upper()
    state = _load()
    record = state.get(key)
    if not record:
        # try match by ip
        for k, v in state.items():
            if v.get("ip") == ip_or_mac:
                key, record = k, v
                break
    if not record:
        return {"ok": False, "error": "not quarantined"}

    if record["method"] == "openwrt":
        _run_router(record.get("router", ""), user, _openwrt_cmd(record["mac"], add=False))
    elif record["method"] == "arp":
        with _lock:
            stop = _arp_threads.pop(key, None)
        if stop:
            stop.set()

    state.pop(key, None); _save(state)
    return {"ok": True, "released": key}


def is_quarantined(ip: str, mac: str) -> bool:
    state = _load()
    return (mac or "").upper() in state or any(v.get("ip") == ip for v in state.values())
