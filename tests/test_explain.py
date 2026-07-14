from netscope import explain

# Every event type the app actually raises must have a real (non-default) explanation.
KNOWN_TYPES = [
    "new_device", "randomized_mac", "mac_rotation", "port_alert", "offline",
    "online", "vulnerability", "port_scan", "vertical_scan", "beaconing",
    "data_exfil", "anomaly", "ids_alert", "threat", "threat_feed", "dns_anomaly",
    "fim", "malware_file", "honeypot", "quarantine",
]


def test_every_known_type_has_plain_language():
    default_meaning = explain._DEFAULT[0]
    for t in KNOWN_TYPES:
        e = explain.explain(t, "warning")
        assert e["meaning"] and e["meaning"] != default_meaning, f"{t} missing meaning"
        assert e["action"], f"{t} missing action"
        assert e["friendly_title"] and e["friendly_title"] != t, f"{t} no friendly title"


def test_no_networking_jargon_in_new_device():
    e = explain.explain("new_device")
    text = (e["meaning"] + " " + e["action"]).lower()
    # Plain-language guarantee: none of these should appear in the explanation.
    for jargon in ("mac address", "subnet", "arp", "oui", "ttl", "packet"):
        assert jargon not in text


def test_severity_labels():
    assert explain.severity_label("critical") == "Needs your attention"
    assert explain.severity_label("warning") == "Worth a look"
    assert explain.severity_label("info") == "For your information"


def test_unknown_type_falls_back_gracefully():
    e = explain.explain("some_new_type_we_dont_know")
    assert e["meaning"] and e["action"]


def test_notify_body_is_plain():
    body = explain.notify_body("data_exfil", "Host uploaded 900 MB to 1.2.3.4", "critical")
    assert "What it means:" in body and "What to do:" in body
    assert "Host uploaded 900 MB" in body


def test_event_dict_carries_explanation(cleandb):
    store = cleandb
    store.add_event("new_device", "New device joined: phone (192.168.1.9)",
                    severity="warning", ip="192.168.1.9")
    ev = store.list_events(limit=1)[0]
    assert ev["friendly_title"] == "New device joined your network"
    assert ev["plain_meaning"] and ev["plain_action"]
    assert ev["severity_label"] == "Worth a look"
