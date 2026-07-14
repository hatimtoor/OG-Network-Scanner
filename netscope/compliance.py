"""Compliance packs (R22).

Runs a set of security controls against the current network/host state and maps
each to common frameworks (PCI DSS, CIS, GDPR-style). Produces a pass/fail
scorecard as JSON and a printable HTML report. This is guidance, not
certification.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from .agent import hostfacts
from .db import store


def _control(cid, title, framework, ok, detail):
    return {"id": cid, "title": title, "framework": framework,
            "status": "pass" if ok else "fail", "detail": detail}


def run() -> dict:
    devices = store.list_devices()
    controls = []

    # NET-1: no cleartext admin protocols (Telnet/FTP) exposed
    cleartext = [(d["display_name"], p["port"]) for d in devices
                 for p in d.get("ports", []) if p.get("port") in (21, 23)]
    controls.append(_control(
        "NET-1", "No cleartext admin protocols (Telnet/FTP)", "PCI DSS 2.2 / CIS 4.5",
        not cleartext,
        "none found" if not cleartext else f"exposed on {len(cleartext)} device(s): "
        + ", ".join(f"{n}:{p}" for n, p in cleartext[:5])))

    # NET-2: no SMB/RDP/VNC exposed
    remote = [(d["display_name"], p["port"]) for d in devices
              for p in d.get("ports", []) if p.get("port") in (445, 3389, 5900)]
    controls.append(_control(
        "NET-2", "Remote/file-sharing services restricted (SMB/RDP/VNC)", "CIS 9 / PCI 1.2",
        not remote,
        "none exposed" if not remote else f"{len(remote)} exposure(s) — ensure LAN-only + strong auth"))

    # VULN-1: no known critical CVEs on inventoried devices
    crit = [c for d in devices for c in d.get("cves", []) if c.get("severity") == "CRITICAL"]
    controls.append(_control(
        "VULN-1", "No known critical vulnerabilities", "PCI DSS 6.1 / GDPR Art.32",
        not crit, "none detected" if not crit else f"{len(crit)} critical CVE(s) found — patch"))

    # HOST-1: host firewall enabled
    hardening = {h["check"]: h for h in hostfacts.hardening_checks()}
    fw = hardening.get("Windows Firewall")
    controls.append(_control(
        "HOST-1", "Host firewall enabled", "CIS 4 / PCI 1.1",
        bool(fw and fw.get("ok")), fw["detail"] if fw else "not evaluated"))

    # HOST-2: remote desktop not exposed
    rdp = hardening.get("Remote Desktop (RDP)")
    controls.append(_control(
        "HOST-2", "Remote Desktop disabled or restricted", "CIS 9 / PCI 8.3",
        bool(rdp and rdp.get("ok")), rdp["detail"] if rdp else "not evaluated"))

    # INV-1: all devices identified (no unknown untrusted)
    unknown = [d for d in devices if d.get("device_type") == "unknown" and not d.get("trusted")]
    controls.append(_control(
        "INV-1", "All devices identified / trusted (asset inventory)", "PCI DSS 2.4 / CIS 1",
        not unknown, "all identified" if not unknown else f"{len(unknown)} unidentified device(s)"))

    passed = sum(1 for c in controls if c["status"] == "pass")
    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "controls": controls,
        "passed": passed,
        "total": len(controls),
        "score": round(100 * passed / max(1, len(controls))),
    }


def html_report() -> str:
    data = run()
    rows = "".join(
        f"<tr class='{c['status']}'><td>{html.escape(c['id'])}</td>"
        f"<td>{html.escape(c['title'])}</td><td>{html.escape(c['framework'])}</td>"
        f"<td class='st'>{'PASS' if c['status']=='pass' else 'FAIL'}</td>"
        f"<td>{html.escape(c['detail'])}</td></tr>"
        for c in data["controls"]
    )
    return f"""<!doctype html><html><head><meta charset='utf-8'>
<title>NetScope Compliance Report</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1a2230}}
h1{{margin:0}} .sub{{color:#667;margin:4px 0 18px}}
.score{{font-size:40px;font-weight:800}}
table{{border-collapse:collapse;width:100%;margin-top:14px;font-size:13px}}
th,td{{border:1px solid #dde;padding:8px 10px;text-align:left}} th{{background:#f4f6fa}}
tr.pass .st{{color:#178f52;font-weight:700}} tr.fail .st{{color:#c0263b;font-weight:700}}
tr.fail td{{background:#fff5f6}}
</style></head><body>
<h1>🛰️ NetScope Compliance Report</h1>
<div class='sub'>Generated {data['generated']} — guidance only, not certification</div>
<div class='score'>{data['score']}%</div>
<div class='sub'>{data['passed']} of {data['total']} controls passed</div>
<table><thead><tr><th>ID</th><th>Control</th><th>Framework</th><th>Status</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""
