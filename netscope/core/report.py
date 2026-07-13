"""Generate a self-contained HTML report of the network.

Summarizes discovered devices, type breakdown, risky exposures, and recent
alerts into a single printable HTML page (no external assets).
"""
from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone

from .. import __app_name__, __version__
from ..config import RISKY_PORTS
from ..db import store
from . import discovery

_TYPE_LABEL = {
    "router": "Router", "phone": "Phone", "computer": "Computer",
    "tv": "TV / Streaming", "printer": "Printer", "iot": "Smart / IoT",
    "game_console": "Game Console", "nas": "NAS / Server", "camera": "Camera",
    "unknown": "Unknown",
}


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def build_html_report() -> str:
    devices = store.list_devices()
    events = store.list_events(limit=100)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    targets = ", ".join(discovery.get_scan_targets())

    online = sum(1 for d in devices if d["is_online"])
    type_counts = Counter(d["device_type"] for d in devices)
    risky_rows = []
    for d in devices:
        risky = [p for p in d.get("ports", []) if p.get("risky")]
        for p in risky:
            risky_rows.append((d["display_name"], d["ip"], p["port"], p["risky"]))

    type_summary = "".join(
        f"<span class='pill'>{_esc(_TYPE_LABEL.get(t, t))}: <b>{c}</b></span>"
        for t, c in type_counts.most_common()
    )

    device_rows = "".join(
        f"<tr><td>{_esc(d['display_name'])}</td><td>{_esc(d['ip'])}</td>"
        f"<td>{_esc(d['mac'])}</td><td>{_esc(_TYPE_LABEL.get(d['device_type'], d['device_type']))}</td>"
        f"<td>{_esc(d['os_guess'])}</td><td>{_esc(d['vendor'])}</td>"
        f"<td>{'online' if d['is_online'] else 'offline'}</td>"
        f"<td>{_esc(','.join(str(p['port']) for p in d.get('ports', [])))}</td></tr>"
        for d in devices
    )

    risky_html = (
        "".join(
            f"<tr><td>{_esc(n)}</td><td>{_esc(ip)}</td><td>{_esc(port)}</td><td>{_esc(desc)}</td></tr>"
            for n, ip, port, desc in risky_rows
        )
        or "<tr><td colspan='4'>No risky ports detected.</td></tr>"
    )

    alert_rows = "".join(
        f"<tr><td>{_esc(e['ts'])}</td><td>{_esc(e['severity'])}</td>"
        f"<td>{_esc(e['type'])}</td><td>{_esc(e['message'])}</td></tr>"
        for e in events[:50]
    ) or "<tr><td colspan='4'>No alerts.</td></tr>"

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{_esc(__app_name__)} Network Report</title>
<style>
  body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #1a2230; }}
  h1 {{ margin: 0; }} .sub {{ color: #667; margin: 4px 0 20px; }}
  .cards {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }}
  .card {{ border: 1px solid #dde; border-radius: 10px; padding: 14px 18px; min-width: 120px; }}
  .card .n {{ font-size: 26px; font-weight: 700; }} .card .l {{ color: #667; font-size: 12px; }}
  .pill {{ display: inline-block; background: #eef2f8; border-radius: 20px; padding: 4px 12px; margin: 3px; font-size: 13px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 10px 0 26px; font-size: 13px; }}
  th, td {{ border: 1px solid #dde; padding: 7px 10px; text-align: left; }}
  th {{ background: #f4f6fa; }}
  h2 {{ border-bottom: 2px solid #eef; padding-bottom: 6px; margin-top: 26px; }}
  .risk td {{ background: #fff4f5; }}
</style></head><body>
<h1>🛰️ {_esc(__app_name__)} Network Report</h1>
<div class="sub">Generated {now} · v{__version__} · Subnets: {_esc(targets)}</div>
<div class="cards">
  <div class="card"><div class="n">{len(devices)}</div><div class="l">Total devices</div></div>
  <div class="card"><div class="n">{online}</div><div class="l">Online now</div></div>
  <div class="card"><div class="n">{len(risky_rows)}</div><div class="l">Risky exposures</div></div>
  <div class="card"><div class="n">{len(events)}</div><div class="l">Recent alerts</div></div>
</div>
<h2>Device types</h2><div>{type_summary or 'No devices.'}</div>
<h2>Device inventory</h2>
<table><thead><tr><th>Name</th><th>IP</th><th>MAC</th><th>Type</th><th>OS</th><th>Vendor</th><th>Status</th><th>Open ports</th></tr></thead>
<tbody>{device_rows}</tbody></table>
<h2>Risky exposures</h2>
<table class="risk"><thead><tr><th>Device</th><th>IP</th><th>Port</th><th>Risk</th></tr></thead><tbody>{risky_html}</tbody></table>
<h2>Recent alerts</h2>
<table><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Message</th></tr></thead><tbody>{alert_rows}</tbody></table>
</body></html>"""
