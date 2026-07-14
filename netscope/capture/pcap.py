"""Rolling full-packet capture (R2).

Prefers Wireshark's ``dumpcap`` (efficient native ring buffer); falls back to a
scapy AsyncSniffer with size-based rotation. Capture is read-only (it never
injects traffic). Off by default because it is resource-intensive and needs
Npcap + privileges. Files are retained as a ring (oldest deleted past the cap).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
from pathlib import Path

from ..config import settings


class PcapManager:
    def __init__(self) -> None:
        self._proc = None
        self._sniffer = None
        self._writer = None
        self._pkts = 0
        self._file_index = 0
        self._lock = threading.Lock()
        self.backend = ""
        self.active = False

    # ---- backend detection ---- #
    @staticmethod
    def dumpcap_path() -> str:
        return shutil.which("dumpcap") or ""

    def detect_backend(self) -> str:
        if self.dumpcap_path():
            return "dumpcap"
        try:
            import scapy.all  # noqa: F401
            return "scapy"
        except Exception:
            return ""

    def _dir(self) -> Path:
        p = Path(settings.pcap_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    # ---- lifecycle ---- #
    def start(self) -> dict:
        if self.active:
            return self.status()
        backend = self.detect_backend()
        if not backend:
            return {"ok": False, "error": "No capture backend (install Wireshark/dumpcap)."}
        try:
            if backend == "dumpcap":
                self._start_dumpcap()
            else:
                self._start_scapy()
            self.backend = backend
            self.active = True
            return self.status()
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _start_dumpcap(self) -> None:
        out = str(self._dir() / "netscope.pcapng")
        args = [self.dumpcap_path(), "-b", f"filesize:{settings.pcap_file_mb * 1024}",
                "-b", f"files:{settings.pcap_max_files}", "-w", out]
        if settings.pcap_interface:
            args += ["-i", settings.pcap_interface]
        self._proc = subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    def _start_scapy(self) -> None:
        from scapy.all import AsyncSniffer, PcapWriter  # type: ignore

        self._file_index = 0
        self._open_writer()

        def _on(pkt):
            with self._lock:
                if self._writer is None:
                    return
                self._writer.write(pkt)
                self._pkts += 1
                if self._pkts % 500 == 0:
                    self._rotate_if_needed()

        self._sniffer = AsyncSniffer(prn=_on, store=False,
                                     iface=settings.pcap_interface or None)
        self._sniffer.start()

    def _open_writer(self) -> None:
        from scapy.all import PcapWriter  # type: ignore

        path = self._dir() / f"netscope-{self._file_index:04d}.pcap"
        self._writer = PcapWriter(str(path), append=False, sync=True)

    def _rotate_if_needed(self) -> None:
        path = self._dir() / f"netscope-{self._file_index:04d}.pcap"
        try:
            if path.exists() and path.stat().st_size >= settings.pcap_file_mb * 1024 * 1024:
                self._writer.close()
                self._file_index += 1
                self._open_writer()
                self._enforce_ring()
        except Exception:
            pass

    def _enforce_ring(self) -> None:
        files = sorted(self._dir().glob("netscope-*.pcap"), key=lambda p: p.stat().st_mtime)
        for old in files[:-settings.pcap_max_files]:
            try:
                old.unlink()
            except Exception:
                pass

    def stop(self) -> dict:
        with self._lock:
            if self._proc is not None:
                try:
                    self._proc.terminate()
                except Exception:
                    pass
                self._proc = None
            if self._sniffer is not None:
                try:
                    self._sniffer.stop()
                except Exception:
                    pass
                self._sniffer = None
            if self._writer is not None:
                try:
                    self._writer.close()
                except Exception:
                    pass
                self._writer = None
            self.active = False
        return self.status()

    # ---- info ---- #
    def list_captures(self) -> list[dict]:
        d = self._dir()
        files = []
        for p in sorted(d.glob("*.pcap*"), key=lambda x: x.stat().st_mtime, reverse=True):
            st = p.stat()
            files.append({"name": p.name, "size_mb": round(st.st_size / 1_048_576, 2),
                          "modified": int(st.st_mtime)})
        return files

    def capture_path(self, name: str) -> str | None:
        # Prevent path traversal; only serve files inside the pcap dir.
        safe = os.path.basename(name)
        p = self._dir() / safe
        return str(p) if p.exists() else None

    def status(self) -> dict:
        files = self.list_captures()
        total = round(sum(f["size_mb"] for f in files), 2)
        return {
            "ok": True,
            "enabled": settings.pcap_enabled,
            "backend": self.backend or self.detect_backend(),
            "active": self.active,
            "files": len(files),
            "total_mb": total,
            "dir": str(self._dir()),
        }


manager = PcapManager()
