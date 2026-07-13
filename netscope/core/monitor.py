"""Background monitor: periodic scans, diffing, events, and notifications."""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from ..config import RISKY_PORTS, settings
from ..db import store
from ..notify import notify
from . import scanner

BroadcastFn = Callable[[dict], Awaitable[None]]


class Monitor:
    """Runs continuous scans and emits state changes.

    ``broadcast`` is an async callback (usually the WebSocket hub) that receives
    dict messages so the dashboard updates in real time.
    """

    def __init__(self, broadcast: BroadcastFn | None = None):
        self.broadcast = broadcast
        self._task: asyncio.Task | None = None
        self._running = False
        self._scanning = False
        self.last_scan_iso: str | None = None

    # ---- lifecycle ---- #
    def start(self) -> None:
        if self._task is None or self._task.done():
            self._running = True
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ---- scanning ---- #
    async def scan_once(self) -> list[dict]:
        """Run one scan in a worker thread and process the results."""
        if self._scanning:
            return store.list_devices()
        self._scanning = True
        await self._emit({"type": "scan_started"})
        try:
            devices = await asyncio.to_thread(scanner.run_scan)
            await self._process(devices)
        finally:
            self._scanning = False
        from datetime import datetime, timezone

        self.last_scan_iso = datetime.now(timezone.utc).isoformat()
        await self._emit({"type": "scan_finished", "count": len(devices)})
        return store.list_devices()

    async def _process(self, devices: list[dict]) -> None:
        seen_keys: set[str] = set()
        for data in devices:
            key = store.device_key(data.get("mac", ""), data.get("ip", ""))
            seen_keys.add(key)
            record, is_new = store.upsert_device(data)

            if is_new:
                name = record.label or record.hostname or record.vendor or record.ip
                msg = (
                    f"New device joined: {name} ({record.ip}) "
                    f"[{record.device_type}]"
                )
                store.add_event(
                    "new_device", msg, severity="warning",
                    mac=record.mac, ip=record.ip,
                )
                notify("New device on your network", msg)
                await self._emit({"type": "new_device", "device": store.get_device(key)})

            # Risky open-port alerts.
            for port_info in data.get("ports", []):
                port = port_info.get("port")
                if port in RISKY_PORTS:
                    name = record.label or record.hostname or record.ip
                    msg = (
                        f"{name} ({record.ip}) exposes {RISKY_PORTS[port]} "
                        f"on port {port}"
                    )
                    store.add_event(
                        "port_alert", msg, severity="warning",
                        mac=record.mac, ip=record.ip,
                    )

        # Devices that disappeared this round.
        for device in store.mark_offline(seen_keys):
            name = device.label or device.hostname or device.ip
            store.add_event(
                "offline", f"{name} ({device.ip}) went offline",
                severity="info", mac=device.mac, ip=device.ip,
            )

        await self._emit({"type": "devices_updated"})

    # ---- helpers ---- #
    async def _loop(self) -> None:
        # Initial scan shortly after startup.
        await asyncio.sleep(1)
        while self._running:
            try:
                await self.scan_once()
            except Exception as exc:  # keep the loop alive
                await self._emit({"type": "error", "message": str(exc)})
            await asyncio.sleep(settings.scan_interval)

    async def _emit(self, message: dict) -> None:
        if self.broadcast:
            try:
                await self.broadcast(message)
            except Exception:
                pass

    @property
    def scanning(self) -> bool:
        return self._scanning
