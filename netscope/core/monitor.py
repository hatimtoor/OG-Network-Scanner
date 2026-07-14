"""Background monitor: periodic scans, diffing, events, and notifications."""
from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable

from ..config import RISKY_PORTS, settings
from ..db import analytics, store
from ..notify import notify, send_html_email
from ..agent import fim
from ..detect import anomaly, baseline, behavioral, dns_analytics
from ..enrich import passive, useragent
from ..security import feeds, mitm, sensor, threatintel, yara_scan
from . import oui, report, scanner, traffic

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
        self.latest_router: list | None = None
        self._checked_ips: set[str] = set()
        self._fired_detections: set[str] = set()
        self._fired_domains: set[str] = set()
        self._last_fim: float = 0.0
        self._last_report: float = 0.0
        self._last_feed_refresh: float = -1e9
        self._feed_hits: set[str] = set()
        self._scanned_files: set[str] = set()

    # ---- lifecycle ---- #
    def start(self) -> None:
        self._running = True
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())
        if self._traffic_task is None or self._traffic_task.done():
            self._traffic_task = asyncio.create_task(self._traffic_loop())
        if settings.passive_enabled:
            try:
                passive.listener.start()  # read-only broadcast sniffing
            except Exception:
                pass

    async def stop(self) -> None:
        self._running = False
        try:
            passive.listener.stop()
        except Exception:
            pass
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

                # MAC-randomization awareness. A device that rotates its MAC shows
                # up as brand-new every time; correlate by fingerprint so we can
                # tell "same device, new MAC" (worth a warning) from an ordinary
                # phone that simply uses a private MAC (logged, but not alarming).
                fp = data.get("fingerprint", "")
                matches = store.find_devices_by_fingerprint(fp, exclude_key=key) if fp else []
                if matches:
                    prior = matches[0]
                    rot = (
                        f"{name} ({record.ip}) matches a previously-seen device "
                        f"'{prior['display_name']}' by fingerprint — its MAC changed "
                        f"from {prior['mac'] or 'n/a'} to {record.mac}. This is normal "
                        "MAC randomization, but can also be used to evade tracking."
                    )
                    store.add_event(
                        "mac_rotation", rot, severity="warning",
                        mac=record.mac, ip=record.ip,
                    )
                    notify("Device changed its MAC address", rot)
                elif oui.is_randomized_mac(record.mac):
                    store.add_event(
                        "randomized_mac",
                        f"{name} ({record.ip}) uses a private/randomized MAC "
                        f"({record.mac}) — its hardware identity is hidden. "
                        "Identified via other signals; verify it is authorized.",
                        severity="info", mac=record.mac, ip=record.ip,
                    )

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
                await self._run_feeds()
                await self._run_behavioral()
                await self._run_dns_detection()
                await self._run_fim()
                await self._run_extract_scan()
                await self._run_scheduled_report()
            except Exception as exc:  # keep the loop alive
                await self._emit({"type": "error", "message": str(exc)})
            await asyncio.sleep(settings.scan_interval)

    async def _run_behavioral(self) -> None:
        """Run flow-based behavioral detections; emit new findings as events."""
        if not settings.behavioral_enabled:
            return
        try:
            detections = await asyncio.to_thread(behavioral.run_detections)
        except Exception:
            return
        new = False
        for d in detections:
            if d.key in self._fired_detections:
                continue
            self._fired_detections.add(d.key)
            store.add_event(
                d.dtype, f"{d.title} — {d.description}", severity=d.severity,
                ip=d.entities.get("remote_ip", "") or d.entities.get("local_ip", ""),
                mitre=d.mitre_id,
            )
            if d.severity in ("warning", "critical"):
                notify(f"Behavioral alert: {d.dtype}", d.title)
            new = True

        # Statistical anomalies (R5) — spikes far outside the learned baseline.
        anomalies = []
        if settings.anomaly_enabled:
            anomalies += anomaly.run()
        if settings.baseline_enabled:
            anomalies += baseline.run()  # pattern-of-life novelty
        for a in anomalies:
            if a.key in self._fired_detections:
                continue
            self._fired_detections.add(a.key)
            store.add_event("anomaly", f"{a.title} — {a.description}",
                            severity=a.severity, mitre=a.mitre_id)
            notify("Anomaly detected", a.title)
            new = True

        if new:
            await self._emit({"type": "detections", "count": len(detections)})

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

        # Zeek conn.log -> whole-network flows; dns.log -> DNS analytics.
        try:
            zeek_flows = await asyncio.to_thread(sensor.poll_new_conn_flows)
            if zeek_flows:
                await asyncio.to_thread(analytics.record_zeek_flows, zeek_flows)
            # Zeek http.log -> User-Agent identification per device.
            for h in await asyncio.to_thread(sensor.poll_new_http):
                ua = useragent.parse(h["user_agent"])
                store.merge_device_details_by_ip(h["ip"], {"user_agent": ua})
            # Decrypted HTTPS from mitmproxy -> UA ID + domain threat check.
            if mitm.configured():
                for f in await asyncio.to_thread(mitm.poll_new_flows):
                    if f.get("user_agent"):
                        store.merge_device_details_by_ip(
                            f["client"], {"user_agent": useragent.parse(f["user_agent"])})
                    host = f.get("host", "")
                    if host and settings.feeds_enabled and feeds.check_domain(host):
                        store.add_event("threat_feed",
                                        f"Decrypted request to known-bad host {host} from {f['client']}",
                                        severity="critical", ip=f["client"], mitre="T1071")
            for domain in await asyncio.to_thread(sensor.poll_new_dns_names):
                if domain not in self._fired_domains:
                    self._fired_domains.add(domain)
                    v = dns_analytics.analyze_domain(domain)
                    if v.suspicious:
                        mitre = "T1568" if v.category == "dga" else "T1572"
                        store.add_event(
                            "dns_anomaly",
                            f"Suspicious DNS ({v.category}): {domain} — {'; '.join(v.reasons)}",
                            severity="warning", mitre=mitre,
                        )
        except Exception:
            pass

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

    async def _run_scheduled_report(self) -> None:
        """Email the HTML network report on a schedule (R21)."""
        hours = settings.report_schedule_hours
        if hours <= 0 or not (settings.report_email or settings.smtp_to):
            return
        if self._last_report and time.monotonic() - self._last_report < hours * 3600:
            return
        self._last_report = time.monotonic()
        try:
            html = await asyncio.to_thread(report.build_html_report)
            sent = await asyncio.to_thread(
                send_html_email, "NetScope network report", html)
            if sent:
                store.add_event("report", "Scheduled network report emailed", severity="info")
        except Exception:
            pass

    async def _run_feeds(self) -> None:
        """Refresh threat-intel feeds on schedule and match against connections."""
        if not settings.feeds_enabled:
            return
        if self._last_feed_refresh < 0:
            await asyncio.to_thread(feeds.load_cache)
        due = time.monotonic() - self._last_feed_refresh >= settings.feed_refresh_hours * 3600
        if due:
            self._last_feed_refresh = time.monotonic()
            await asyncio.to_thread(feeds.refresh)
        if not feeds.available():
            return
        try:
            conns = await asyncio.to_thread(traffic.get_connections, 200)
        except Exception:
            return
        for c in conns:
            ip = c.remote_ip
            if not ip or ip in self._feed_hits or traffic._is_local_net(ip):
                continue
            if feeds.check_ip(ip):
                self._feed_hits.add(ip)
                msg = f"Connection to known-bad IP {ip} (threat-intel feed match) via {c.process}"
                store.add_event("threat_feed", msg, severity="critical", ip=ip, mitre="T1071")
                notify("Malicious IP contacted", msg)
                await self._emit({"type": "threat", "ip": ip, "verdict": "feed"})

    async def _run_extract_scan(self) -> None:
        """Scan files Zeek/Strelka extracted from traffic for malware (R17)."""
        import os
        if not settings.extract_dir or not os.path.isdir(settings.extract_dir):
            return
        try:
            for name in os.listdir(settings.extract_dir):
                path = os.path.join(settings.extract_dir, name)
                if path in self._scanned_files or not os.path.isfile(path):
                    continue
                self._scanned_files.add(path)
                res = await asyncio.to_thread(yara_scan.scan_file, path, True)
                feed_hit = feeds.check_hash(res.sha256)
                bad = res.vt_verdict == "malicious" or res.yara_matches or feed_hit
                if bad:
                    detail = res.vt_verdict
                    if res.yara_matches:
                        detail += " / YARA:" + ",".join(res.yara_matches)
                    if feed_hit:
                        detail += " / threat-feed hash match"
                    store.add_event("malware_file", f"Malicious extracted file {name} ({detail})",
                                    severity="critical", mitre="T1105")
                    notify("Malware in traffic", f"{name}: {detail}")
        except Exception:
            pass

    async def _run_fim(self) -> None:
        """Periodic file-integrity scan; alerts on modified/deleted watched files."""
        if not (settings.host_agent_enabled and fim.configured()):
            return
        if time.monotonic() - self._last_fim < settings.fim_interval:
            return
        self._last_fim = time.monotonic()
        try:
            result = await asyncio.to_thread(fim.scan)
        except Exception:
            return
        if result.get("first_run"):
            return
        for p in result.get("modified", []):
            store.add_event("fim", f"Watched file modified: {p}", severity="warning", mitre="T1565")
        for p in result.get("deleted", []):
            store.add_event("fim", f"Watched file deleted: {p}", severity="warning", mitre="T1070")
        if result.get("modified") or result.get("deleted"):
            notify("File integrity alert",
                   f"{len(result.get('modified', []))} modified, {len(result.get('deleted', []))} deleted")

    async def _run_dns_detection(self) -> None:
        """Analyze recently-seen DNS queries for DGA / tunneling patterns."""
        if not settings.behavioral_enabled:
            return
        try:
            domains = passive.listener.recent_domains()
        except Exception:
            return
        for domain in list(domains.keys()):
            if domain in self._fired_domains:
                continue
            self._fired_domains.add(domain)
            if settings.feeds_enabled and feeds.check_domain(domain):
                store.add_event("threat_feed", f"DNS query to known-bad domain {domain} (feed match)",
                                severity="critical", ip=domains[domain].get("src", ""), mitre="T1071")
                notify("Malicious domain queried", domain)
                continue
            verdict = dns_analytics.analyze_domain(domain)
            if not verdict.suspicious:
                continue
            mitre = "T1568" if verdict.category == "dga" else "T1572"
            msg = f"Suspicious DNS ({verdict.category}): {domain} — {'; '.join(verdict.reasons)}"
            store.add_event("dns_anomaly", msg, severity="warning",
                            ip=domains[domain].get("src", ""), mitre=mitre)
            notify("Suspicious DNS query", f"{verdict.category}: {domain}")

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
                if settings.flow_record:
                    await asyncio.to_thread(analytics.record_connections, snap.connections)
                if settings.snmp_router:
                    from ..enrich import snmp as _snmp
                    self.latest_router = await asyncio.to_thread(
                        _snmp.interface_rates, settings.snmp_router,
                        settings.snmp_router_community, time.monotonic())
                await self._emit({"type": "traffic", "traffic": {
                    "sent_rate": tp.sent_rate, "recv_rate": tp.recv_rate,
                    "connections": len(snap.connections),
                }})
                sample_count += 1
                if sample_count % 100 == 0:
                    await asyncio.to_thread(store.prune_traffic)
                    if settings.flow_record:
                        await asyncio.to_thread(analytics.prune)
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
