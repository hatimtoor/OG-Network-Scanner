"""FastAPI application: REST endpoints, WebSocket hub, and static dashboard."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .. import __app_name__, __version__
from ..config import settings
from ..core import discovery
from ..core.monitor import Monitor
from ..db import store

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
    monitor.start()
    yield
    await monitor.stop()


app = FastAPI(title=__app_name__, version=__version__, lifespan=lifespan)


# --------------------------------------------------------------------------- #
# REST API
# --------------------------------------------------------------------------- #
@app.get("/api/status")
async def get_status() -> dict:
    return {
        "app": __app_name__,
        "version": __version__,
        "subnet": discovery.detect_subnet(),
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


@app.get("/api/events")
async def get_events(limit: int = 100) -> list[dict]:
    return store.list_events(limit=limit)


@app.post("/api/events/acknowledge")
async def ack_events() -> dict:
    return {"acknowledged": store.acknowledge_events()}


@app.post("/api/scan")
async def trigger_scan() -> dict:
    # Fire-and-forget so the request returns immediately.
    asyncio.create_task(monitor.scan_once())
    return {"status": "scan_started"}


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
