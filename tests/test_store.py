"""Tests for netscope/db/store.py + models.py.

Covers: device upsert/get, event creation (incl. mitre/case_id), case CRUD,
dashboard_counts, search_events, save_device_details, merge_device_details_by_ip,
and list_traffic_history.  Uses the `cleandb` fixture for isolation.
"""
from netscope.db import store


def test_upsert_device_creates_new_device(cleandb):
    device, is_new = store.upsert_device(
        {"mac": "AA:BB:CC:DD:EE:01", "ip": "10.0.0.1",
         "device_type": "computer", "vendor": "Acme Corp"}
    )
    assert is_new is True
    assert device.ip == "10.0.0.1"
    assert device.vendor == "Acme Corp"


def test_upsert_device_updates_existing_device(cleandb):
    store.upsert_device({"mac": "AA:BB:CC:DD:EE:02", "ip": "10.0.0.2",
                         "device_type": "phone"})
    device, is_new = store.upsert_device(
        {"mac": "AA:BB:CC:DD:EE:02", "ip": "10.0.0.2",
         "device_type": "phone", "hostname": "my-phone"}
    )
    assert is_new is False
    assert device.hostname == "my-phone"


def test_get_device_returns_expected_dict_keys(cleandb):
    store.upsert_device({"mac": "AA:BB:CC:DD:EE:03", "ip": "10.0.0.3"})
    key = store.device_key("AA:BB:CC:DD:EE:03", "10.0.0.3")
    result = store.get_device(key)
    assert result is not None
    for field in ("id", "key", "mac", "ip", "display_name", "ports", "details", "cves"):
        assert field in result
    assert result["ip"] == "10.0.0.3"


def test_add_event_stores_mitre_and_case_id_is_none(cleandb):
    evt = store.add_event(
        "port_alert", "RDP exposed on 10.0.0.1",
        severity="critical", ip="10.0.0.1", mitre="T1021.001"
    )
    assert evt["type"] == "port_alert"
    assert evt["severity"] == "critical"
    assert evt["mitre"] == "T1021.001"
    assert evt["case_id"] is None
    assert evt["acknowledged"] is False
    assert evt["ts"] is not None


def test_create_case_and_retrieve_it(cleandb):
    case = store.create_case("Test incident", severity="warning")
    assert case["title"] == "Test incident"
    assert case["status"] == "open"
    assert case["severity"] == "warning"
    assert case["event_count"] == 0

    fetched = store.get_case(case["id"])
    assert fetched is not None
    assert fetched["id"] == case["id"]
    assert "events" in fetched


def test_update_case_changes_title_and_status(cleandb):
    case = store.create_case("Original title")
    updated = store.update_case(case["id"], title="Updated title", status="investigating")
    assert updated is not None
    assert updated["title"] == "Updated title"
    assert updated["status"] == "investigating"


def test_dashboard_counts_aggregates_by_severity_and_mitre(cleandb):
    store.add_event("e1", "info message", severity="info")
    store.add_event("e2", "warning message", severity="warning")
    store.add_event("e3", "critical message", severity="critical", mitre="T1046")

    counts = store.dashboard_counts()
    assert counts["total"] >= 3
    assert counts["severity"].get("critical", 0) >= 1
    assert counts["severity"].get("warning", 0) >= 1
    assert any(m["name"] == "T1046" for m in counts["mitre"])
    assert "types" in counts


def test_search_events_finds_by_message_substring(cleandb):
    store.add_event("custom", "unique-xylophone-probe detected", severity="info",
                    ip="1.2.3.4")
    hits = store.search_events("xylophone")
    assert hits
    assert any("xylophone" in e["message"] for e in hits)


def test_search_events_returns_empty_for_blank_query(cleandb):
    result = store.search_events("")
    assert result == []


def test_save_device_details_persists_details_and_cves(cleandb):
    store.upsert_device({"mac": "AA:BB:CC:DD:EE:05", "ip": "10.0.0.5"})
    key = store.device_key("AA:BB:CC:DD:EE:05", "10.0.0.5")
    result = store.save_device_details(
        key,
        {"banner": "Apache/2.4"},
        [{"id": "CVE-2021-1234", "severity": "CRITICAL"}],
    )
    assert result is not None
    assert result["details"]["banner"] == "Apache/2.4"
    assert any(c["id"] == "CVE-2021-1234" for c in result["cves"])
    assert result["deep_scanned_at"] is not None


def test_merge_device_details_by_ip_merges_extra_fields(cleandb):
    store.upsert_device({"mac": "AA:BB:CC:DD:EE:06", "ip": "10.0.0.6"})
    ok = store.merge_device_details_by_ip("10.0.0.6", {"upnp_model": "Router X"})
    assert ok is True
    key = store.device_key("AA:BB:CC:DD:EE:06", "10.0.0.6")
    result = store.get_device(key)
    assert result["details"]["upnp_model"] == "Router X"


def test_list_traffic_history_returns_expected_keys(cleandb):
    store.add_traffic_sample(100.0, 200.0, 1000, 2000, 5)
    store.add_traffic_sample(150.0, 250.0, 1500, 2500, 8)
    history = store.list_traffic_history()
    assert len(history) >= 2
    for row in history:
        assert "ts" in row
        assert "sent_rate" in row
        assert "recv_rate" in row
        assert "connections" in row
