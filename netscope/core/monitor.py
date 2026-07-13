"""Background monitor: periodic scans, diffing, events, and notifications."""
from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable

from ..config import RISKY_PORTS, settings
from ..db import store
from ..notify import notify
from ..security import sensor, threatintel
from . import scanner, traffic

BroadcastFn = Callable[[dict], Awaitable[None]]


class Monitor:
    """Runs continuous scans and emits state changes.

    ``broadcast`` is an async callback (usually the WebSocket hub) that receives
    dict messages so the dashboard updates in real time.
    """

    def __init__(self, broadcast: BroadcastFn | None = None):
        self.broadcast = broadcast
        self._task: asyncio.Task | None = None
        self._traffic_task: asyncio.Task | None = None
        self._running = False
        self._scanning = False
        self.last_scan_iso: str | None = None
        self._meter = traffic.TrafficMeter()
        self.latest_traffic: dict | None = None
        self._checked_ips: set[str] = set()

    # ---- lifecycle ---- #
    def start(self) -> None:
        self._running = True
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())
        if self._traffic_task is None or self._traffic_task.done():
            self._traffic_task = asyncio.create_task(self._traffic_loop())

    async def stop(self) -> None:
        self._running = False
        for task in (self._task, self._traffic_task):
            if task:
                task.cancel()
                try:
                    await task
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
                await self._poll_security()
            except Exception as exc:  # keep the loop alive
                await self._emit({"type": "error", "message": str(exc)})
            await asyncio.sleep(settings.scan_interval)

    async def _poll_security(self) -> None:
        """Ingest new IDS alerts and optionally reputation-check external IPs."""
        # 1) Suricata/Zeek IDS alerts appended since last poll.
        try:
            alerts = await asyncio.to_thread(sensor.poll_new_alerts)
        except Exception:
            alerts = []
        for a in alerts:
            msg = f"[{a.source}] {a.signature} ({a.src_ip} -> {a.dest_ip})"
            store.add_event("ids_alert", msg, severity=a.severity, ip=a.src_ip)
            if a.severity in ("warning", "critical"):
                notify("IDS alert", a.signature or msg)
        if alerts:
            await self._emit({"type": "ids_alerts", "count": len(alerts)})

        # 2) Optional reputation check of new external IPs this host talks to.
        if not (settings.threat_auto_check and threatintel.available()):
            return
        try:
            conns = await asyncio.to_thread(traffic.get_connections, 200)
        except Exception:
            return
        externals = [
            c.remote_ip for c in conns
            if c.remote_ip and not traffic._is_local_net(c.remote_ip)
            and not c.remote_ip.startswith("127.")
        ]
        new_ips = [ip for ip in dict.fromkeys(externals) if ip not in self._checked_ips][:5]
        for ip in new_ips:
            self._checked_ips.add(ip)
            verdict = await asyncio.to_thread(threatintel.check_ip, ip)
            if verdict.verdict in ("malicious", "suspicious"):
                msg = f"Connection to {verdict.verdict} IP {ip} ({verdict.detail})"
                store.add_event("threat", msg, severity="critical", ip=ip)
                notify("Malicious connection detected", msg)
                await self._emit({"type": "threat", "ip": ip, "verdict": verdict.verdict})

    async def _traffic_loop(self) -> None:
        """Sample host throughput on a fast cadence for live charts."""
        sample_count = 0
        while self._running:
            try:
                snap = await asyncio.to_thread(traffic.snapshot, self._meter, time.monotonic())
                tp = snap.throughput
                self.latest_traffic = {
                    "sent_rate": tp.sent_rate,
                    "recv_rate": tp.recv_rate,
                    "bytes_sent": tp.bytes_sent,
                    "bytes_recv": tp.bytes_recv,
                    "connections": len(snap.connections),
                    "per_device_conns": snap.per_device_conns,
                }
                store.add_traffic_sample(
                    tp.sent_rate, tp.recv_rate, tp.bytes_sent, tp.bytes_recv,
                    len(snap.connections),
                )
                await self._emit({"type": "traffic", "traffic": {
                    "sent_rate": tp.sent_rate, "recv_rate": tp.recv_rate,
                    "connections": len(snap.connections),
                }})
                sample_count += 1
                if sample_count % 100 == 0:
                    await asyncio.to_thread(store.prune_traffic)
            except Exception:
                pass
            await asyncio.sleep(settings.traffic_interval)

    async def _emit(self, message: dict) -> None:
        if self.broadcast:
            try:
                await self.broadcast(message)
            except Exception:
                pass

    @property
    def scanning(self) -> bool:
        return self._scanning
