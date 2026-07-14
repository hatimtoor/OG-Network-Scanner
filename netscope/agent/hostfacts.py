"""Collect host facts: OS, users, listening ports, software inventory, hardening.

The manager runs on the host, so this is a built-in "agent" for the local
machine (a remote agent is a later step). Wazuh-inspired but intentionally
lightweight and dependency-free (stdlib + psutil).
"""
from __future__ import annotations

import platform
import socket
import subprocess
import sys

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

IS_WINDOWS = sys.platform.startswith("win")


def os_info() -> dict:
    info = {
        "hostname": socket.gethostname(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }
    if psutil is not None:
        try:
            import time
            info["uptime_hours"] = round((time.time() - psutil.boot_time()) / 3600, 1)
        except Exception:
            pass
    return info


def listening_ports() -> list[dict]:
    if psutil is None:
        return []
    out = []
    proc_cache: dict[int, str] = {}
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status != "LISTEN" or not c.laddr:
                continue
            name = ""
            if c.pid:
                if c.pid not in proc_cache:
                    try:
                        proc_cache[c.pid] = psutil.Process(c.pid).name()
                    except Exception:
                        proc_cache[c.pid] = ""
                name = proc_cache[c.pid]
            out.append({"port": c.laddr.port, "address": c.laddr.ip,
                        "pid": c.pid, "process": name})
    except Exception:
        return out
    # De-dup by (port, process)
    seen, uniq = set(), []
    for r in sorted(out, key=lambda x: x["port"]):
        k = (r["port"], r["process"])
        if k not in seen:
            seen.add(k); uniq.append(r)
    return uniq


def logged_in_users() -> list[dict]:
    if psutil is None:
        return []
    try:
        return [{"name": u.name, "terminal": u.terminal or "", "host": u.host or ""}
                for u in psutil.users()]
    except Exception:
        return []


def installed_software(limit: int = 800) -> list[dict]:
    """Best-effort installed-software inventory (used for CVE matching)."""
    if IS_WINDOWS:
        return _windows_software(limit)
    return _unix_software(limit)


def _windows_software(limit: int) -> list[dict]:
    import winreg

    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    seen, out = set(), []
    for hive, path in roots:
        try:
            key = winreg.OpenKey(hive, path)
        except Exception:
            continue
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                name = winreg.QueryValueEx(sub, "DisplayName")[0]
            except Exception:
                continue
            try:
                version = winreg.QueryValueEx(sub, "DisplayVersion")[0]
            except Exception:
                version = ""
            try:
                pub = winreg.QueryValueEx(sub, "Publisher")[0]
            except Exception:
                pub = ""
            key_id = (name, version)
            if name and key_id not in seen:
                seen.add(key_id)
                out.append({"name": name, "version": version, "publisher": pub})
            if len(out) >= limit:
                break
    return sorted(out, key=lambda x: x["name"].lower())


def _unix_software(limit: int) -> list[dict]:
    for cmd, parse in (
        (["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], "dpkg"),
        (["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"], "rpm"),
    ):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
        except Exception:
            continue
        rows = []
        for line in out.splitlines()[:limit]:
            parts = line.split("\t")
            if len(parts) >= 2:
                rows.append({"name": parts[0], "version": parts[1], "publisher": ""})
        if rows:
            return rows
    return []


def hardening_checks() -> list[dict]:
    """A few common posture checks (best effort, Windows-focused)."""
    checks: list[dict] = []
    if IS_WINDOWS:
        checks.append(_win_firewall())
        checks.append(_win_rdp())
    else:
        checks.append({"check": "SSH root login", "status": "unknown",
                       "ok": None, "detail": "not evaluated"})
    return [c for c in checks if c]


def _win_firewall() -> dict:
    try:
        out = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"],
                             capture_output=True, text=True, timeout=10).stdout.lower()
        on = out.count("state") > 0 and "off" not in out
        return {"check": "Windows Firewall", "status": "on" if on else "some profiles off",
                "ok": on, "detail": "all profiles enabled" if on else "review profiles"}
    except Exception:
        return {"check": "Windows Firewall", "status": "unknown", "ok": None, "detail": ""}


def _win_rdp() -> dict:
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server")
        deny = winreg.QueryValueEx(key, "fDenyTSConnections")[0]
        enabled = deny == 0
        return {"check": "Remote Desktop (RDP)",
                "status": "enabled" if enabled else "disabled",
                "ok": not enabled,
                "detail": "RDP is exposed — ensure it's needed and firewalled" if enabled else "disabled"}
    except Exception:
        return {"check": "Remote Desktop (RDP)", "status": "unknown", "ok": None, "detail": ""}


def collect() -> dict:
    software = installed_software()
    return {
        "os": os_info(),
        "users": logged_in_users(),
        "listening_ports": listening_ports(),
        "software_count": len(software),
        "software": software[:300],
        "hardening": hardening_checks(),
    }
