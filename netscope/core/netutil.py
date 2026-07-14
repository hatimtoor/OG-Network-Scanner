"""Small networking helpers shared across modules."""
from __future__ import annotations

import ipaddress


def is_private_ip(ip: str) -> bool:
    """True if ``ip`` is a private / local / non-routable address.

    Uses the stdlib ``ipaddress`` module so the whole RFC-1918 space is handled
    correctly — crucially ``172.16.0.0/12`` only, NOT all of ``172.0.0.0/8``.
    A naive ``ip.startswith("172.")`` wrongly marks public ranges like Cloudflare
    (``172.67.x``) and Google (``172.217.x``) as "local", which silently excludes
    them from external-flow detection, threat-feed matching, and reputation checks.

    Also treats loopback and link-local as local. Unparseable input -> False
    (treated as external, i.e. worth checking) rather than silently trusted.
    """
    try:
        obj = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return False
    return obj.is_private or obj.is_loopback or obj.is_link_local
