"""Centralized logging + an in-memory error surface.

Previously the codebase had no logging at all, so a failed scan or probe was
indistinguishable from "all clear". This sets up a rotating log file plus a small
in-memory ring buffer of recent warnings/errors that the dashboard can show, so
failures are visible instead of silently swallowed.
"""
from __future__ import annotations

import collections
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path

from .config import settings

_RING: collections.deque = collections.deque(maxlen=200)
_CONFIGURED = False


class _RingHandler(logging.Handler):
    """Keeps the most recent WARNING+ records for the /api/health surface."""

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno < logging.WARNING:
            return
        try:
            _RING.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            })
        except Exception:
            pass


def setup_logging() -> None:
    """Idempotently configure root logging (file + console + ring buffer)."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    root = logging.getLogger("netscope")
    root.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    try:
        log_path = Path(settings.db_path).resolve().parent / "netscope.log"
        fileh = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        fileh.setFormatter(fmt)
        root.addHandler(fileh)
    except Exception:
        pass  # file logging is best-effort; console + ring still work

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    console.setLevel(logging.WARNING)
    root.addHandler(console)

    root.addHandler(_RingHandler())
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"netscope.{name}")


def recent_errors(limit: int = 50) -> list[dict]:
    """Most-recent-first list of recent warnings/errors."""
    return list(_RING)[-limit:][::-1]
