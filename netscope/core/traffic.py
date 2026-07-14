"""Traffic & bandwidth monitoring for the host running NetScope.

Important scope note: a normal host on a switched network can only measure its
own throughput and its own connections — it cannot see the byte counts of other
devices' traffic without a router (SNMP) or a mirror/SPAN port (sensor mode,
v3). So this module reports:

  - Real-time upload/download throughput of this machine (accurate).
  - The list of this machine's active connections, attributed to LAN devices
    when the remote IP is on the local network.
  - A per-device *connection count* as a lightweight activity signal.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field

from .netutil import is_private_ip

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


@dataclass
class Throughput:
    bytes_sent: int = 0
    bytes_recv: int = 0
    sent_rate: float = 0.0  # bytes/sec since last sample
    recv_rate: float = 0.0


@dataclass
class Connection:
    local: str = ""
    remote: str = ""
    remote_ip: str = ""
    remote_port: int = 0
    status: str = ""
    pid: int | None = None
    process: str = ""


@dataclass
class TrafficSnapshot:
    throughput: Throughput = field(default_factory=Throughput)
    connections: list[Connection] = field(default_factory=list)
    per_device_conns: dict[str, int] = field(default_factory=dict)  # ip -> count


class TrafficMeter:
    """Stateful meter that computes throughput rates between samples."""

    def __init__(self) -> None:
        self._last_sent = 0
        self._last_recv = 0
        self._last_ts: float | None = None

    def _totals(self) -> tuple[int, int]:
        if psutil is None:
            return 0, 0
        io = psutil.net_io_counters()
        return io.bytes_sent, io.bytes_recv

    def sample(self, now: float) -> Throughput:
        sent, recv = self._totals()
        tp = Throughput(bytes_sent=sent, bytes_recv=recv)
        if self._last_ts is not None and now > self._last_ts:
            dt = now - self._last_ts
            tp.sent_rate = max(0.0, (sent - self._last_sent) / dt)
            tp.recv_rate = max(0.0, (recv - self._last_recv) / dt)
        self._last_sent, self._last_recv, self._last_ts = sent, recv, now
        return tp


def _is_local_net(ip: str) -> bool:
    return is_private_ip(ip)


def get_connections(limit: int = 200) -> list[Connection]:
    """Return this host's active inet connections with process names."""
    if psutil is None:
        return []
    conns: list[Connection] = []
    try:
        raw = psutil.net_connections(kind="inet")
    except Exception:
        return []

    proc_cache: dict[int, str] = {}
    for c in raw:
        if not c.raddr:
            continue
        rip = c.raddr.ip
        rport = c.raddr.port
        name = ""
        if c.pid:
            if c.pid not in proc_cache:
                try:
                    proc_cache[c.pid] = psutil.Process(c.pid).name()
                except Exception:
                    proc_cache[c.pid] = ""
            name = proc_cache[c.pid]
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        conns.append(
            Connection(
                local=laddr,
                remote=f"{rip}:{rport}",
                remote_ip=rip,
                remote_port=rport,
                status=c.status,
                pid=c.pid,
                process=name,
            )
        )
        if len(conns) >= limit:
            break
    return conns


def snapshot(meter: TrafficMeter, now: float) -> TrafficSnapshot:
    tp = meter.sample(now)
    conns = get_connections()
    per_device: dict[str, int] = {}
    for c in conns:
        if _is_local_net(c.remote_ip):
            per_device[c.remote_ip] = per_device.get(c.remote_ip, 0) + 1
    return TrafficSnapshot(throughput=tp, connections=conns, per_device_conns=per_device)


def hostname_for(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
