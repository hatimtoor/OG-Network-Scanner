"""FastAPI application: REST endpoints, WebSocket hub, and static dashboard."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import csv
import io

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .. import __app_name__, __version__
from ..config import settings
from ..core import discovery, report, traffic
from ..core.monitor import Monitor
from ..agent import fim, hostfacts
from ..capture import pcap
from ..db import analytics, store
from ..detect import playbooks
from ..enrich import cve, deepscan
from ..response import quarantine
from ..security import feeds, sensor, threatintel, yara_scan

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


class WebSocketHub:
    """Tracks connected dashboards and broadcasts JSON messages to them."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, message: dict) -> None:
        async with self._lock:
            clients = list(self._clients)
        for ws in clients:
            try:
                await ws.send_json(message)
            except Exception:
                await self.disconnect(ws)


hub = WebSocketHub()
monitor = Monitor(broadcast=hub.broadcast)


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db()
    analytics.init()
    monitor.start()
    if settings.pcap_enabled:
        pcap.manager.start()
    yield
    pcap.manager.stop()
    await monitor.stop()


app = FastAPI(title=__app_name__, version=__version__, lifespan=lifespan)


# --------------------------------------------------------------------------- #
# REST API
# --------------------------------------------------------------------------- #
@app.get("/api/status")
async def get_status() -> dict:
    targets = discovery.get_scan_targets()
    return {
        "app": __app_name__,
        "version": __version__,
        "subnet": targets[0] if targets else "",
        "subnets": targets,
        "gateway": discovery.get_gateway_ip(),
        "local_ip": discovery.get_local_ip(),
        "scanning": monitor.scanning,
        "last_scan": monitor.last_scan_iso,
        "scan_interval": settings.scan_interval,
    }


@app.get("/api/devices")
async def get_devices() -> list[dict]:
    return store.list_devices()


@app.get("/api/devices/{key}")
async def get_device(key: str):
    device = store.get_device(key)
    if device is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return device


@app.patch("/api/devices/{key}")
async def patch_device(key: str, body: dict):
    device = store.update_device_meta(
        key, label=body.get("label"), trusted=body.get("trusted")
    )
    if device is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    await hub.broadcast({"type": "devices_updated"})
    return device


@app.post("/api/devices/{key}/deepscan")
async def deep_scan_device(key: str):
    device = store.get_device(key)
    if device is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    open_ports = [p.get("port") for p in device.get("ports", []) if p.get("port")]
    result = await asyncio.to_thread(
        deepscan.deep_scan, device["ip"], device.get("mac", ""), open_ports
    )
    updated = store.save_device_details(key, result["details"], result["cves"])

    # Raise alerts for any high-severity CVEs found.
    for c in result["cves"]:
        if c.get("severity") in ("CRITICAL", "HIGH"):
            store.add_event(
                "vulnerability",
                f"{device['display_name']} ({device['ip']}): {c['id']} "
                f"{c['severity']} - {c.get('source_hint', '')}",
                severity="critical", ip=device["ip"], mac=device.get("mac", ""),
            )
    await hub.broadcast({"type": "devices_updated"})
    return updated or {"error": "save failed"}


@app.get("/api/events")
async def get_events(limit: int = 100) -> list[dict]:
    events = store.list_events(limit=limit)
    for e in events:
        pb = playbooks.for_type(e.get("type", ""))
        if pb:
            e["playbook"] = pb
    return events


# --------------------------------------------------------------------------- #
# Active response (quarantine) — explicit, consented, reversible
# --------------------------------------------------------------------------- #
@app.get("/api/response/quarantined")
async def get_quarantined() -> list[dict]:
    return quarantine.list_quarantined()


@app.post("/api/response/quarantine")
async def do_quarantine(body: dict):
    key = (body or {}).get("key", "")
    device = store.get_device(key)
    if device is None:
        return JSONResponse({"error": "device not found"}, status_code=404)
    gateway = discovery.get_gateway_ip()
    if device["ip"] in (gateway, discovery.get_local_ip()):
        return JSONResponse({"error": "refusing to quarantine the gateway or this host"},
                            status_code=400)
    result = await asyncio.to_thread(
        quarantine.quarantine, device["ip"], device.get("mac", ""),
        body.get("method", "arp"), body.get("router", ""),
        body.get("user", "root"), gateway, int(body.get("duration_minutes", 0) or 0),
    )
    if result.get("ok"):
        store.add_event("quarantine",
                        f"Device quarantined: {device['display_name']} ({device['ip']}) "
                        f"via {body.get('method', 'arp')}",
                        severity="warning", ip=device["ip"], mac=device.get("mac", ""))
        await hub.broadcast({"type": "devices_updated"})
    return result


@app.post("/api/response/release")
async def do_release(body: dict):
    result = await asyncio.to_thread(quarantine.release, (body or {}).get("key", ""))
    if result.get("ok"):
        store.add_event("quarantine", f"Device released from quarantine: {body.get('key')}",
                        severity="info")
        await hub.broadcast({"type": "devices_updated"})
    return result


@app.get("/api/playbooks")
async def get_playbooks() -> dict:
    return playbooks.all_playbooks()


@app.post("/api/events/acknowledge")
async def ack_events() -> dict:
    return {"acknowledged": store.acknowledge_events()}


# --------------------------------------------------------------------------- #
# Cases (basic incident response)
# --------------------------------------------------------------------------- #
@app.get("/api/cases")
async def get_cases() -> list[dict]:
    return store.list_cases()


@app.post("/api/cases")
async def create_case(body: dict):
    title = (body or {}).get("title", "").strip() or "Untitled case"
    case = store.create_case(
        title, severity=body.get("severity", "info"), event_ids=body.get("event_ids"),
    )
    await hub.broadcast({"type": "cases_updated"})
    return case


@app.get("/api/cases/{case_id}")
async def get_case(case_id: int):
    case = store.get_case(case_id)
    if case is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return case


@app.patch("/api/cases/{case_id}")
async def patch_case(case_id: int, body: dict):
    case = store.update_case(case_id, **(body or {}))
    if case is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    await hub.broadcast({"type": "cases_updated"})
    return case


@app.post("/api/cases/{case_id}/events")
async def add_case_events(case_id: int, body: dict):
    case = store.link_events_to_case(case_id, (body or {}).get("event_ids", []))
    if case is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    await hub.broadcast({"type": "cases_updated"})
    return case


@app.post("/api/scan")
async def trigger_scan() -> dict:
    # Fire-and-forget so the request returns immediately.
    asyncio.create_task(monitor.scan_once())
    return {"status": "scan_started"}


# --------------------------------------------------------------------------- #
# Traffic & bandwidth
# --------------------------------------------------------------------------- #
@app.get("/api/traffic")
async def get_traffic() -> dict:
    conns = await asyncio.to_thread(traffic.get_connections, 200)
    latest = monitor.latest_traffic or {}
    return {
        "throughput": {
            "sent_rate": latest.get("sent_rate", 0.0),
            "recv_rate": latest.get("recv_rate", 0.0),
            "connections": latest.get("connections", len(conns)),
        },
        "per_device_conns": latest.get("per_device_conns", {}),
        "connections": [c.__dict__ for c in conns],
    }


@app.get("/api/traffic/history")
async def get_traffic_history(limit: int = 180) -> list[dict]:
    return store.list_traffic_history(limit=limit)


# --------------------------------------------------------------------------- #
# Flows / hunting (DuckDB analytics)
# --------------------------------------------------------------------------- #
@app.get("/api/flows")
async def get_flows(
    search: str = "", remote_ip: str = "", process: str = "",
    port: int | None = None, external_only: bool = False, limit: int = 200,
) -> list[dict]:
    return await asyncio.to_thread(
        analytics.query_flows, remote_ip, process, port, external_only, search, limit
    )


@app.get("/api/flows/top")
async def get_top_talkers(limit: int = 15) -> list[dict]:
    return await asyncio.to_thread(analytics.top_talkers, limit, True)


@app.get("/api/flows/stats")
async def get_flow_stats() -> dict:
    return await asyncio.to_thread(analytics.stats)


@app.get("/api/flows/bandwidth")
async def get_device_bandwidth(limit: int = 50) -> list[dict]:
    rows = await asyncio.to_thread(analytics.device_bandwidth, limit)
    by_ip = {d["ip"]: d["display_name"] for d in store.list_devices()}
    for r in rows:
        r["name"] = by_ip.get(r["ip"], r["ip"])
    return rows


# --------------------------------------------------------------------------- #
# Packet capture (PCAP)
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Host agent (facts, FIM, inventory vulnerabilities)
# --------------------------------------------------------------------------- #
@app.get("/api/host/facts")
async def host_facts() -> dict:
    return await asyncio.to_thread(hostfacts.collect)


@app.get("/api/host/fim")
async def host_fim_status() -> dict:
    return fim.status()


@app.post("/api/host/fim/scan")
async def host_fim_scan() -> dict:
    result = await asyncio.to_thread(fim.scan)
    if not result.get("first_run"):
        for p in result.get("modified", []):
            store.add_event("fim", f"File modified: {p}", severity="warning", mitre="T1565")
        for p in result.get("deleted", []):
            store.add_event("fim", f"File deleted: {p}", severity="warning", mitre="T1070")
    return result


@app.post("/api/host/vulns")
async def host_vulns(body: dict):
    software = (body or {}).get("software")
    if not software:
        facts = await asyncio.to_thread(hostfacts.collect)
        software = facts.get("software", [])
    # Cap products to respect NVD rate limits; prefer versioned entries.
    hints = [f"{s['name']} {s['version']}".strip()
             for s in software if s.get("version")][:12]
    cves = await asyncio.to_thread(cve.correlate, hints, 12, 2)
    return {"checked": len(hints), "cves": cves}


@app.get("/api/pcap/status")
async def pcap_status() -> dict:
    return pcap.manager.status()


@app.get("/api/pcap/list")
async def pcap_list() -> list[dict]:
    return pcap.manager.list_captures()


@app.post("/api/pcap/start")
async def pcap_start() -> dict:
    return await asyncio.to_thread(pcap.manager.start)


@app.post("/api/pcap/stop")
async def pcap_stop() -> dict:
    return await asyncio.to_thread(pcap.manager.stop)


@app.get("/api/pcap/download/{name}")
async def pcap_download(name: str):
    path = pcap.manager.capture_path(name)
    if path is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(path, filename=Path(path).name,
                        media_type="application/vnd.tcpdump.pcap")


# --------------------------------------------------------------------------- #
# Exports
# --------------------------------------------------------------------------- #
def _csv_response(rows: list[dict], columns: list[str], filename: str) -> Response:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/export/devices.csv")
async def export_devices() -> Response:
    rows = store.list_devices()
    for r in rows:
        r["open_ports"] = ",".join(str(p["port"]) for p in r.get("ports", []))
    cols = ["ip", "mac", "display_name", "device_type", "os_guess", "vendor",
            "confidence", "trusted", "is_online", "open_ports", "first_seen", "last_seen"]
    return _csv_response(rows, cols, "netscope-devices.csv")


@app.get("/api/export/events.csv")
async def export_events() -> Response:
    rows = store.list_events(limit=1000)
    cols = ["ts", "severity", "type", "ip", "mac", "message"]
    return _csv_response(rows, cols, "netscope-events.csv")


@app.get("/api/report")
async def network_report() -> Response:
    html_doc = await asyncio.to_thread(report.build_html_report)
    return Response(
        content=html_doc,
        media_type="text/html",
        headers={"Content-Disposition": 'attachment; filename="netscope-report.html"'},
    )


# --------------------------------------------------------------------------- #
# Security (v3): threat intel, IDS sensor, YARA
# --------------------------------------------------------------------------- #
@app.get("/api/security/status")
async def security_status() -> dict:
    return {
        "virustotal": threatintel.available(),
        "sensor_configured": sensor.configured(),
        "suricata_path": settings.suricata_eve_path,
        "zeek_dir": settings.zeek_log_dir,
        "yara": yara_scan.yara_available(),
        "auto_check": settings.threat_auto_check,
        "feeds": feeds.status(),
    }


@app.get("/api/security/feeds")
async def get_feeds() -> dict:
    return feeds.status()


@app.post("/api/security/feeds/refresh")
async def refresh_feeds() -> dict:
    return await asyncio.to_thread(feeds.refresh)


@app.get("/api/security/ids-alerts")
async def ids_alerts(limit: int = 200) -> list[dict]:
    return await asyncio.to_thread(sensor.all_alerts, limit)


@app.post("/api/security/check-ip")
async def check_ip(body: dict):
    ip = (body or {}).get("ip", "").strip()
    if not ip:
        return JSONResponse({"error": "ip required"}, status_code=400)
    verdict = await asyncio.to_thread(threatintel.check_ip, ip)
    return verdict.to_dict()


@app.post("/api/security/scan-file")
async def scan_file(body: dict):
    path = (body or {}).get("path", "").strip()
    if not path:
        return JSONResponse({"error": "path required"}, status_code=400)
    result = await asyncio.to_thread(yara_scan.scan_file, path, True)
    return result.to_dict()


# --------------------------------------------------------------------------- #
# WebSocket
# --------------------------------------------------------------------------- #
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keepalive; we ignore inbound content
    except WebSocketDisconnect:
        await hub.disconnect(ws)
    except Exception:
        await hub.disconnect(ws)


# --------------------------------------------------------------------------- #
# Static dashboard (mounted last so /api and /ws take priority)
# --------------------------------------------------------------------------- #
@app.get("/")
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
