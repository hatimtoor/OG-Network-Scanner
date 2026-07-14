"""Entrypoint: ``python -m netscope`` launches the API + background monitor."""
from __future__ import annotations

import webbrowser
from threading import Timer

import uvicorn

from . import __app_name__, __version__
from .config import settings


def _loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1", "localhost")


def main() -> None:
    # Safety guard: never expose an unauthenticated instance on the network by
    # accident. Binding a non-loopback host with auth off is refused unless the
    # user explicitly opts in (and is nudged to turn auth on instead).
    if not _loopback(settings.host) and not settings.auth_enabled and not settings.allow_insecure_bind:
        print(
            f"\n  REFUSING TO START: binding {settings.host} exposes NetScope on your "
            "network with NO authentication.\n"
            "  Fix one of these:\n"
            "    - set NETSCOPE_AUTH=true and NETSCOPE_PASSWORD=... (recommended), or\n"
            "    - bind locally with NETSCOPE_HOST=127.0.0.1, or\n"
            "    - if you really intend an open instance, set NETSCOPE_ALLOW_INSECURE_BIND=true\n"
        )
        raise SystemExit(2)

    url = f"http://{settings.host}:{settings.port}"
    print(f"\n  {__app_name__} v{__version__}")
    print(f"  Dashboard:  {url}")
    print(f"  Scanning every {settings.scan_interval}s. Press Ctrl+C to stop.\n")

    # Open the dashboard in the default browser shortly after startup.
    if settings.open_browser and settings.host in {"127.0.0.1", "0.0.0.0", "localhost"}:
        Timer(1.5, lambda: webbrowser.open(url)).start()

    uvicorn.run(
        "netscope.api.server:app",
        host=settings.host,
        port=settings.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
