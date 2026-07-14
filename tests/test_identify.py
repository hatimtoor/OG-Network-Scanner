from netscope.core import identify, oui


def test_router_by_gateway():
    r = identify.identify(mac="50:C7:BF:11:22:33", ip="192.168.1.1", gateway_ip="192.168.1.1")
    assert r.device_type == "router"
    assert r.confidence == 100


def test_randomized_mac_phone():
    p = identify.identify(mac="7A:11:22:33:44:55", ip="192.168.1.20",
                          hostname="Johns-iPhone", open_ports=[62078], ttl=64)
    assert p.device_type == "phone"
    assert oui.is_randomized_mac("7A:11:22:33:44:55") is True
    assert "iOS" in p.os_guess


def test_windows_computer():
    c = identify.identify(mac="00:1C:B3:00:00:01", ip="192.168.1.30",
                          open_ports=[445, 139, 3389], ttl=128)
    assert c.device_type == "computer"
    assert "Windows" in c.os_guess


def test_printer_and_tv():
    pr = identify.identify(mac="00:11:22:33:44:66", ip="192.168.1.40",
                           hostname="HP-LaserJet", open_ports=[9100, 631])
    assert pr.device_type == "printer"
    tv = identify.identify(mac="F0:D2:F1:00:00:02", ip="192.168.1.50",
                           open_ports=[8009], mdns_services=["_googlecast._tcp.local."])
    assert tv.device_type == "tv"


def test_randomized_mac_vendor_hidden():
    assert oui.lookup_vendor("7A:11:22:33:44:55") == "Private (randomized MAC)"


def test_bare_randomized_phone_not_computer():
    # A phone that hides everything (randomized MAC, no hostname, no open ports,
    # mobile TTL) must NOT be called a computer — this was the live-test bug.
    r = identify.identify(mac="7A:AB:CD:EF:00:11", ip="192.168.1.21", ttl=64)
    assert r.device_type == "phone"


def test_windows_pc_stays_computer_despite_no_hostname():
    r = identify.identify(mac="00:1C:B3:00:00:02", ip="192.168.1.30",
                          open_ports=[445, 139, 3389], ttl=128)
    assert r.device_type == "computer"


def test_mac_laptop_with_smb_is_computer_not_phone():
    # macOS randomizes its MAC too, but a real computer advertises SMB/SSH — the
    # phone-lean must not override that evidence.
    r = identify.identify(mac="7A:11:22:33:44:99", ip="192.168.1.31",
                          open_ports=[22, 445], ttl=64,
                          mdns_services=["_smb._tcp.local."])
    assert r.device_type == "computer"
