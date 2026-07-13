"""SQLModel tables for devices and events."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Device(SQLModel, table=True):
    """A device seen on the network.

    ``key`` uniquely identifies the device: the MAC address when known,
    otherwise ``ip:<address>`` so hosts without a resolvable MAC still persist.
    """

    id: int | None = Field(default=None, primary_key=True)
    key: str = Field(index=True, unique=True)
    mac: str = Field(default="", index=True)
    ip: str = Field(default="")
    hostname: str = Field(default="")
    vendor: str = Field(default="")
    device_type: str = Field(default="unknown")
    os_guess: str = Field(default="")
    confidence: int = Field(default=0)

    # User-editable
    label: str = Field(default="")
    trusted: bool = Field(default=False)

    # State
    is_online: bool = Field(default=True)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)

    # JSON-encoded detail
    ports_json: str = Field(default="[]")
    reasons_json: str = Field(default="[]")

    # Deep enrichment (UPnP/SNMP/banners/passive) + vulnerability findings
    details_json: str = Field(default="{}")
    cves_json: str = Field(default="[]")
    deep_scanned_at: datetime | None = Field(default=None)


class TrafficSample(SQLModel, table=True):
    """A point-in-time throughput sample for the host, used for trend charts."""

    id: int | None = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=utcnow, index=True)
    sent_rate: float = Field(default=0.0)   # bytes/sec upload
    recv_rate: float = Field(default=0.0)   # bytes/sec download
    bytes_sent: int = Field(default=0)      # cumulative counter
    bytes_recv: int = Field(default=0)
    connections: int = Field(default=0)     # active connection count


class Event(SQLModel, table=True):
    """An alert / audit event (new device, online/offline, risky port)."""

    id: int | None = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=utcnow, index=True)
    type: str = Field(default="info")        # new_device | online | offline | port_alert | info
    severity: str = Field(default="info")    # info | warning | critical
    mac: str = Field(default="")
    ip: str = Field(default="")
    message: str = Field(default="")
    acknowledged: bool = Field(default=False)
