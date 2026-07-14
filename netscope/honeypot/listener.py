"""Decoy TCP listeners (honeypots).

Any connection to a honeypot port is, by definition, suspicious — nothing
legitimate should be talking to it. A hit raises a critical alert identifying the
source, which is an excellent early-warning signal for a device scanning your LAN
or an attacker probing for services. Off by default.
"""
from __future__ import annotations

import asyncio

from ..config import settings

# Fake banners so a casual probe thinks it found a real service.
_BANNERS = {
    23: b"\r\nUbuntu 22.04 LTS\r\nlogin: ",
    2323: b"\r\nlogin: ",
    3389: b"",
    8081: b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n\r\n",
}


class Honeypot:
    def __init__(self, on_hit=None) -> None:
        self._servers: list = []
        self.on_hit = on_hit
        self.active = False
        self.ports: list[int] = []

    def _parse_ports(self) -> list[int]:
        out = []
        for tok in settings.honeypot_ports.split(","):
            tok = tok.strip()
            if tok.isdigit():
                out.append(int(tok))
        return out

    async def start(self) -> None:
        if self.active:
            return
        self.ports = self._parse_ports()
        for port in self.ports:
            try:
                server = await asyncio.start_server(
                    self._make_handler(port), host="0.0.0.0", port=port
                )
                self._servers.append(server)
            except Exception:
                continue
        self.active = bool(self._servers)

    def _make_handler(self, port: int):
        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            peer = writer.get_extra_info("peername")
            src_ip = peer[0] if peer else "?"
            try:
                if self.on_hit:
                    self.on_hit(src_ip, port)
                writer.write(_BANNERS.get(port, b""))
                await writer.drain()
                await asyncio.sleep(0.5)
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass
        return handler

    async def stop(self) -> None:
        for server in self._servers:
            try:
                server.close()
            except Exception:
                pass
        self._servers = []
        self.active = False

    def status(self) -> dict:
        return {"enabled": settings.honeypot_enabled, "active": self.active,
                "ports": self.ports}


honeypot = Honeypot()
