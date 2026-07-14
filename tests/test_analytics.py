from types import SimpleNamespace


def _conn(remote_ip, remote_port=443, local="192.168.1.30:5000", process="chrome.exe"):
    return SimpleNamespace(remote_ip=remote_ip, remote_port=remote_port,
                           local=local, process=process)


def test_record_connections_and_query(flows):
    conns = [_conn("8.8.8.8"), _conn("8.8.8.8"), _conn("1.1.1.1", 53)]
    new = flows.record_connections(conns)
    assert new == 2  # two distinct flow keys, one repeat
    rows = flows.query_flows(remote_ip="8.8.8.8")
    assert rows and rows[0]["remote_ip"] == "8.8.8.8"
    assert rows[0]["samples"] == 2


def test_zeek_flows_bandwidth_and_exfil(flows):
    flows.record_zeek_flows([
        {"local_ip": "192.168.1.30", "remote_ip": "203.0.113.9", "remote_port": 443,
         "protocol": "tcp", "bytes_sent": 120_000_000, "bytes_recv": 5_000},
    ])
    bw = flows.device_bandwidth()
    assert any(d["ip"] == "192.168.1.30" and d["bytes_sent"] == 120_000_000 for d in bw)
    exfil = flows.exfil_candidates(min_bytes=50_000_000)
    assert exfil and exfil[0]["remote_ip"] == "203.0.113.9"


def test_stats_and_top_talkers(flows):
    flows.record_connections([_conn("9.9.9.9"), _conn("9.9.9.9"), _conn("192.168.1.1")])
    st = flows.stats()
    assert st["total_flows"] >= 2
    talkers = flows.top_talkers(external_only=True)
    assert any(t["remote_ip"] == "9.9.9.9" for t in talkers)


def test_packet_index(flows):
    rows = [
        ("2026-01-01 00:00:00", "192.168.1.30", "8.8.8.8", 5000, 53, "udp", 80, "a.pcap", 1),
        ("2026-01-01 00:00:01", "192.168.1.30", "1.1.1.1", 5001, 443, "tcp", 512, "a.pcap", 2),
    ]
    assert flows.record_packets(rows) == 2
    hits = flows.search_packets(port=443)
    assert hits and hits[0]["dst_port"] == 443
    assert flows.packet_stats()["total"] == 2
