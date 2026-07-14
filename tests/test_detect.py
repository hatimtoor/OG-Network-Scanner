import datetime as dt

from netscope.detect import anomaly, baseline, behavioral


def _insert(analytics, **kw):
    base = dt.datetime(2026, 1, 1, 12, 0, 0)
    row = {
        "flow_key": kw["flow_key"], "local_ip": kw.get("local_ip", "192.168.1.30"),
        "remote_ip": kw["remote_ip"], "remote_port": kw.get("remote_port", 443),
        "protocol": "tcp", "process": kw.get("process", "evil.exe"),
        "remote_is_local": kw.get("remote_is_local", False),
        "first_seen": kw.get("first_seen", base), "last_seen": kw.get("last_seen", base),
        "samples": kw.get("samples", 1), "bytes_sent": kw.get("bytes_sent", 0),
        "bytes_recv": 0, "source": "test",
    }
    with analytics._lock:
        analytics._conn.execute(
            """INSERT INTO flows (flow_key, local_ip, remote_ip, remote_port, protocol,
               process, remote_is_local, first_seen, last_seen, samples, bytes_sent,
               bytes_recv, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [row["flow_key"], row["local_ip"], row["remote_ip"], row["remote_port"],
             row["protocol"], row["process"], row["remote_is_local"], row["first_seen"],
             row["last_seen"], row["samples"], row["bytes_sent"], row["bytes_recv"],
             row["source"]],
        )


def test_horizontal_scan(flows):
    for i in range(25):
        _insert(flows, flow_key=f"h{i}", remote_ip=f"203.0.113.{i}", process="nmap.exe")
    dets = behavioral.run_detections()
    assert any(d.dtype == "port_scan" and d.mitre_id == "T1046" for d in dets)


def test_vertical_scan(flows):
    for p in range(20):
        _insert(flows, flow_key=f"v{p}", remote_ip="203.0.113.50", remote_port=1000 + p)
    dets = behavioral.run_detections()
    assert any(d.dtype == "vertical_scan" for d in dets)


def test_beaconing(flows):
    base = dt.datetime(2026, 1, 1, 12, 0, 0)
    _insert(flows, flow_key="beacon1", remote_ip="198.51.100.7", samples=60,
            first_seen=base, last_seen=base + dt.timedelta(seconds=1800))
    dets = behavioral.run_detections()
    assert any(d.dtype == "beaconing" and d.mitre_id.startswith("T1071") for d in dets)


def test_data_exfil(flows):
    _insert(flows, flow_key="exf1", remote_ip="198.51.100.9", bytes_sent=200_000_000)
    dets = behavioral.run_detections()
    assert any(d.dtype == "data_exfil" and d.severity == "critical" for d in dets)


def test_throughput_anomaly_flat_baseline(monkeypatch):
    hist = [{"recv_rate": 1000.0, "sent_rate": 500.0} for _ in range(40)]
    hist[-1] = {"recv_rate": 80_000_000.0, "sent_rate": 500.0}
    monkeypatch.setattr("netscope.detect.anomaly.store.list_traffic_history",
                        lambda limit=240: hist)
    a = anomaly.throughput_anomaly()
    assert a is not None and "download" in a.title.lower()


def test_baseline_lifecycle(flows):
    baseline.reset()
    assert baseline.status()["established"] in (True, False)
    # not enough flows yet -> no anomalies, establishes/holds baseline gracefully
    assert isinstance(baseline.run(), list)
