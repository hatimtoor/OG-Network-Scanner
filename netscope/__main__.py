"""Entrypoint: ``python -m netscope`` launches the API + background monitor."""
from __future__ import annotations

import webbrowser
from threading import Timer

import uvicorn

from . import __app_name__, __version__
from .config import settings


def main() -> None:
    url = f"http://{settings.host}:{settings.port}"
    print(f"\n  {__app_name__} v{__version__}")
    print(f"  Dashboard:  {url}")
    print(f"  Scanning every {settings.scan_interval}s. Press Ctrl+C to stop.\n")

    # Open the dashboard in the default browser shortly after startup.
    if settings.host in {"127.0.0.1", "0.0.0.0", "localhost"}:
        Timer(1.5, lambda: webbrowser.open(url)).start()

    uvicorn.run(
        "netscope.api.server:app",
        host=settings.host,
        port=settings.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
