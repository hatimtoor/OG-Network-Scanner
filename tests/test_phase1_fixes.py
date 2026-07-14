"""Phase 1 correctness + security fixes."""
import time

import pytest

from netscope.core.netutil import is_private_ip


@pytest.mark.parametrize("ip,expected", [
    ("172.16.0.1", True), ("172.31.255.254", True), ("172.20.10.1", True),
    ("172.15.0.1", False), ("172.32.0.1", False),
    ("172.67.1.1", False), ("172.217.14.1", False),   # Cloudflare / Google (public!)
    ("10.0.0.5", True), ("192.168.1.1", True), ("127.0.0.1", True),
    ("169.254.1.1", True), ("8.8.8.8", False), ("1.1.1.1", False),
    ("not-an-ip", False), ("", False),
])
def test_private_ip_classification(ip, expected):
    assert is_private_ip(ip) is expected


def test_auth_token_roundtrip_and_expiry():
    from netscope.api import auth
    tok = auth.create_token("admin")
    assert auth.verify_token(tok) == "admin"
    # tampered signature fails
    assert auth.verify_token(tok[:-1] + ("0" if tok[-1] != "0" else "1")) is None
    # already-expired token fails
    expired = auth.create_token("admin", ttl=-10)
    assert auth.verify_token(expired) is None
    # malformed tokens fail
    assert auth.verify_token("garbage") is None
    assert auth.verify_token("") is None


def test_quarantine_rejects_injection():
    from netscope.response import quarantine as q
    r = q.quarantine(ip="192.168.1.9", mac="x; reboot", method="openwrt", router="192.168.1.1")
    assert not r["ok"] and "MAC" in r["error"]
    r = q.quarantine(ip="192.168.1.9", mac="AA:BB:CC:DD:EE:FF", method="openwrt",
                     router="1.2.3.4; rm -rf /")
    assert not r["ok"] and "router" in r["error"]
    assert q._valid_mac("AA:BB:CC:DD:EE:FF") and not q._valid_mac("x; reboot")
    assert q._valid_host("192.168.1.1") and not q._valid_host("a; b")


def test_event_pruning(cleandb):
    store = cleandb
    from datetime import timedelta
    from netscope.db.models import Event, utcnow
    with store.get_session() as s:
        s.add(Event(type="info", message="old", ts=utcnow() - timedelta(days=90)))
        s.add(Event(type="info", message="fresh", ts=utcnow()))
        s.commit()
    deleted = store.prune_events(retention_days=30)
    assert deleted == 1
    remaining = [e["message"] for e in store.list_events(limit=10)]
    assert "fresh" in remaining and "old" not in remaining


def test_health_endpoint_reports_errors():
    import asyncio
    from netscope import log
    from netscope.api import server
    log.setup_logging()
    log.get_logger("test").warning("phase1 health probe message")
    h = asyncio.run(server.health())
    assert h["ok"] is True and "version" in h
    assert any("phase1 health probe" in e["message"] for e in h["recent_errors"])


def test_file_scan_path_confinement(monkeypatch):
    from netscope.api import server
    from netscope.config import settings
    # No scan dir configured -> disabled, never touches arbitrary files.
    monkeypatch.setattr(settings, "extract_dir", "")
    monkeypatch.setattr(settings, "pcap_dir", "")
    safe, err = server._confined_scan_path("/etc/shadow")
    assert safe == "" and "disabled" in err
