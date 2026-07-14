"""Tests for netscope/capture/pcap_index.py.

Requires scapy; the whole module is skipped if scapy cannot be imported.
Builds a tiny synthetic pcap in tmp_path and verifies that index_file()
parses it and returns packets in the expected shape.  Uses the `flows`
fixture to clear the packets table before each test.
"""
import pytest

pytest.importorskip("scapy")


def test_index_synthetic_pcap_parses_udp_and_tcp_packets(tmp_path, flows):
    from scapy.layers.inet import IP, UDP, TCP
    from scapy.utils import wrpcap

    pkts = [
        IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=53),
        IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=12345),
        IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=54321, dport=443),
    ]
    pcap_path = str(tmp_path / "test.pcap")
    wrpcap(pcap_path, pkts)

    from netscope.capture.pcap_index import index_file
    result = index_file(pcap_path)

    assert "error" not in result, f"Indexing failed: {result.get('error')}"
    assert result["file"] == "test.pcap"
    assert result["indexed"] == 3  # all three packets were read

    # Packets must be searchable by port in the analytics store.
    hits_dns = flows.search_packets(port=53)
    assert hits_dns, "Expected packets with port 53 in the index"
    assert any(h["dst_port"] == 53 or h["src_port"] == 53 for h in hits_dns)

    hits_https = flows.search_packets(port=443)
    assert hits_https, "Expected packet with port 443 in the index"
    assert hits_https[0]["dst_port"] == 443 or hits_https[0]["src_port"] == 443


def test_index_file_not_found_returns_error(tmp_path, flows):
    from netscope.capture.pcap_index import index_file
    result = index_file(str(tmp_path / "nonexistent.pcap"))
    assert "error" in result
    assert result["error"] == "file not found"


def test_index_already_indexed_file_returns_skip_note(tmp_path, flows):
    from scapy.layers.inet import IP, UDP
    from scapy.utils import wrpcap
    from netscope.capture.pcap_index import index_file

    pcap_path = str(tmp_path / "repeated.pcap")
    wrpcap(pcap_path, [IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1000, dport=2000)])

    result_first = index_file(pcap_path)
    assert "error" not in result_first

    result_second = index_file(pcap_path)
    assert result_second.get("note") == "already indexed"
    assert result_second["indexed"] == 0
