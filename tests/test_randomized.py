"""MAC-randomization handling: fingerprinting, correlation, deep-scan output."""
from netscope.core import identify
from netscope.core.portscan import PortResult, ScanResult
from netscope.enrich import deepscan


def test_fingerprint_stable_across_mac_change():
    a = identify.fingerprint(hostname="Johns-Laptop", open_ports=[445, 139],
                             mdns_services=["_smb._tcp.local."], dhcp_os="Windows")
    b = identify.fingerprint(hostname="johns-laptop", open_ports=[139, 445],
                             mdns_services=["_smb._tcp.local."], dhcp_os="windows")
    assert a and a == b  # same signals -> same fingerprint regardless of MAC


def test_fingerprint_empty_when_no_signal():
    # No hostname and only one weak signal -> not safe to fingerprint.
    assert identify.fingerprint(open_ports=[443]) == ""
    assert identify.fingerprint() == ""


def test_fingerprint_two_weak_signals_is_enough():
    fp = identify.fingerprint(open_ports=[62078], mdns_services=["_airplay._tcp.local."])
    assert fp != ""


def test_device_dict_exposes_randomized_flag(cleandb):
    store = cleandb
    store.upsert_device({"mac": "7A:11:22:33:44:55", "ip": "192.168.1.50",
                         "hostname": "phone", "fingerprint": "abc123"})
    dev = store.get_device("7A:11:22:33:44:55")
    assert dev["randomized_mac"] is True
    assert dev["fingerprint"] == "abc123"


def test_find_devices_by_fingerprint_correlates_mac_rotation(cleandb):
    store = cleandb
    fp = "deadbeefcafe0001"
    store.upsert_device({"mac": "AA:BB:CC:00:00:01", "ip": "192.168.1.10",
                         "hostname": "same-laptop", "fingerprint": fp})
    store.upsert_device({"mac": "7A:99:88:77:66:55", "ip": "192.168.1.11",
                         "hostname": "same-laptop", "fingerprint": fp})
    matches = store.find_devices_by_fingerprint(fp, exclude_key="7A:99:88:77:66:55")
    assert len(matches) == 1
    assert matches[0]["mac"] == "AA:BB:CC:00:00:01"
    # An empty fingerprint must never correlate.
    assert store.find_devices_by_fingerprint("") == []


def test_deep_scan_always_returns_identity(monkeypatch):
    monkeypatch.setattr(deepscan, "_reverse_dns", lambda ip: "test-host.local")
    monkeypatch.setattr(deepscan, "_netbios_name", lambda ip: "")
    monkeypatch.setattr(deepscan, "_ping", lambda ip: (1.0, 128))
    monkeypatch.setattr(
        deepscan.portscan, "scan",
        lambda ip: ScanResult(ports=[PortResult(port=445, service="smb")], method="socket"),
    )
    r = deepscan.deep_scan(ip="192.168.1.30", mac="7A:11:22:33:44:55")
    d = r["details"]
    assert d["reverse_dns"] == "test-host.local"
    assert d["randomized_mac"] is True
    assert d["ttl"] == 128 and d["latency_ms"] == 1.0
    assert d["identity"]["device_type"] and "confidence" in d["identity"]
    assert d["services"] and d["services"][0]["port"] == 445
