"""Database access helpers (engine, upserts, queries)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlmodel import Session, SQLModel, create_engine, select

from ..config import settings
from .models import Device, Event, TrafficSample, utcnow

_engine = create_engine(
    f"sqlite:///{settings.db_path}",
    connect_args={"check_same_thread": False},
)


def init_db() -> None:
    SQLModel.metadata.create_all(_engine)
    _migrate()


def _migrate() -> None:
    """Add columns introduced in newer versions to a pre-existing database.

    create_all() creates missing tables but never alters existing ones, so an
    older netscope.db would be missing the newer Device columns. SQLite supports
    ADD COLUMN, which is all we need.
    """
    additions = {
        "details_json": "TEXT DEFAULT '{}'",
        "cves_json": "TEXT DEFAULT '[]'",
        "deep_scanned_at": "DATETIME",
    }
    try:
        with _engine.connect() as conn:
            existing = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(device)")}
            if not existing:
                return
            for name, ddl in additions.items():
                if name not in existing:
                    conn.exec_driver_sql(f"ALTER TABLE device ADD COLUMN {name} {ddl}")
            conn.commit()
    except Exception:
        pass


def get_session() -> Session:
    return Session(_engine)


# --------------------------------------------------------------------------- #
# Devices
# --------------------------------------------------------------------------- #
def device_key(mac: str, ip: str) -> str:
    return mac.upper() if mac else f"ip:{ip}"


def upsert_device(data: dict) -> tuple[Device, bool]:
    """Insert or update a device. Returns (device, is_new)."""
    key = device_key(data.get("mac", ""), data.get("ip", ""))
    with get_session() as session:
        device = session.exec(select(Device).where(Device.key == key)).first()
        is_new = device is None
        if device is None:
            device = Device(key=key, first_seen=utcnow())

        # Update discovered fields (never overwrite user label/trusted).
        for field_name in (
            "mac", "ip", "hostname", "vendor", "device_type", "os_guess", "confidence"
        ):
            if field_name in data and data[field_name] not in (None, ""):
                setattr(device, field_name, data[field_name])

        if "ports" in data:
            device.ports_json = json.dumps(data["ports"])
        if "reasons" in data:
            device.reasons_json = json.dumps(data["reasons"])

        # Light auto-enrichment merged from the scan (UPnP/mDNS/passive).
        if data.get("details"):
            merged = json.loads(device.details_json or "{}")
            merged.update(data["details"])
            device.details_json = json.dumps(merged)

        device.is_online = True
        device.last_seen = utcnow()

        session.add(device)
        session.commit()
        session.refresh(device)
    return device, is_new


def mark_offline(seen_keys: set[str], stale_seconds: int = 0) -> list[Device]:
    """Mark devices not in ``seen_keys`` as offline. Returns newly-offline ones."""
    newly_offline: list[Device] = []
    with get_session() as session:
        devices = session.exec(select(Device).where(Device.is_online == True)).all()  # noqa: E712
        for device in devices:
            if device.key not in seen_keys:
                device.is_online = False
                session.add(device)
                newly_offline.append(device)
        session.commit()
    return newly_offline


def list_devices() -> list[dict]:
    with get_session() as session:
        devices = session.exec(select(Device).order_by(Device.ip)).all()
        return [_device_to_dict(d) for d in devices]


def get_device(key: str) -> dict | None:
    with get_session() as session:
        device = session.exec(select(Device).where(Device.key == key)).first()
        return _device_to_dict(device) if device else None


def update_device_meta(key: str, label: str | None, trusted: bool | None) -> dict | None:
    with get_session() as session:
        device = session.exec(select(Device).where(Device.key == key)).first()
        if device is None:
            return None
        if label is not None:
            device.label = label
        if trusted is not None:
            device.trusted = trusted
        session.add(device)
        session.commit()
        session.refresh(device)
        return _device_to_dict(device)


def _device_to_dict(d: Device) -> dict:
    return {
        "id": d.id,
        "key": d.key,
        "mac": d.mac,
        "ip": d.ip,
        "hostname": d.hostname,
        "vendor": d.vendor,
        "device_type": d.device_type,
        "os_guess": d.os_guess,
        "confidence": d.confidence,
        "label": d.label,
        "trusted": d.trusted,
        "is_online": d.is_online,
        "first_seen": d.first_seen.isoformat() if d.first_seen else None,
        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        "ports": json.loads(d.ports_json or "[]"),
        "reasons": json.loads(d.reasons_json or "[]"),
        "details": json.loads(d.details_json or "{}"),
        "cves": json.loads(d.cves_json or "[]"),
        "deep_scanned_at": d.deep_scanned_at.isoformat() if d.deep_scanned_at else None,
        "display_name": d.label or d.hostname or d.vendor or d.ip,
    }


def save_device_details(key: str, details: dict, cves: list) -> dict | None:
    """Persist on-demand deep-scan results for a device."""
    with get_session() as session:
        device = session.exec(select(Device).where(Device.key == key)).first()
        if device is None:
            return None
        merged = json.loads(device.details_json or "{}")
        merged.update(details or {})
        device.details_json = json.dumps(merged)
        device.cves_json = json.dumps(cves or [])
        device.deep_scanned_at = utcnow()
        session.add(device)
        session.commit()
        session.refresh(device)
        return _device_to_dict(device)


# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #
def add_event(
    type: str, message: str, *, severity: str = "info", mac: str = "", ip: str = ""
) -> dict:
    with get_session() as session:
        event = Event(type=type, message=message, severity=severity, mac=mac, ip=ip)
        session.add(event)
        session.commit()
        session.refresh(event)
        return _event_to_dict(event)


def list_events(limit: int = 100) -> list[dict]:
    with get_session() as session:
        events = session.exec(select(Event).order_by(Event.ts.desc()).limit(limit)).all()
        return [_event_to_dict(e) for e in events]


def acknowledge_events() -> int:
    with get_session() as session:
        events = session.exec(select(Event).where(Event.acknowledged == False)).all()  # noqa: E712
        for e in events:
            e.acknowledged = True
            session.add(e)
        session.commit()
        return len(events)


def _event_to_dict(e: Event) -> dict:
    return {
        "id": e.id,
        "ts": e.ts.isoformat() if e.ts else None,
        "type": e.type,
        "severity": e.severity,
        "mac": e.mac,
        "ip": e.ip,
        "message": e.message,
        "acknowledged": e.acknowledged,
    }


# --------------------------------------------------------------------------- #
# Traffic history
# --------------------------------------------------------------------------- #
def add_traffic_sample(
    sent_rate: float, recv_rate: float, bytes_sent: int, bytes_recv: int, connections: int
) -> None:
    with get_session() as session:
        session.add(
            TrafficSample(
                sent_rate=sent_rate,
                recv_rate=recv_rate,
                bytes_sent=bytes_sent,
                bytes_recv=bytes_recv,
                connections=connections,
            )
        )
        session.commit()


def list_traffic_history(limit: int = 180) -> list[dict]:
    """Return the most recent samples in chronological (oldest-first) order."""
    with get_session() as session:
        rows = session.exec(
            select(TrafficSample).order_by(TrafficSample.ts.desc()).limit(limit)
        ).all()
    rows.reverse()
    return [
        {
            "ts": r.ts.isoformat() if r.ts else None,
            "sent_rate": r.sent_rate,
            "recv_rate": r.recv_rate,
            "connections": r.connections,
        }
        for r in rows
    ]


def prune_traffic(keep: int = 5000) -> None:
    """Cap the traffic table so the DB doesn't grow without bound."""
    with get_session() as session:
        ids = session.exec(
            select(TrafficSample.id).order_by(TrafficSample.ts.desc()).offset(keep)
        ).all()
        if not ids:
            return
        for sample in session.exec(select(TrafficSample).where(TrafficSample.id.in_(ids))).all():
            session.delete(sample)
        session.commit()
