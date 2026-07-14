import hashlib
import struct

from netscope.detect import dns_analytics as dns
from netscope.detect import tls


def test_dns_clean_domains():
    for d in ("google.com", "www.microsoft.com"):
        assert dns.analyze_domain(d).suspicious is False


def test_dns_dga():
    v = dns.analyze_domain("kq3v9z7j1xw8f2plmn4c.com")
    assert v.suspicious and v.category == "dga"


def test_dns_tunneling():
    v = dns.analyze_domain(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil-exfil-domain-tunnel.example.com")
    assert v.suspicious and v.category == "tunneling"


def _u16(v):
    return struct.pack(">H", v)


def _build_client_hello():
    sni = b"example.com"
    sni_ext = _u16(0) + _u16(len(sni) + 5) + _u16(len(sni) + 3) + b"\x00" + _u16(len(sni)) + sni
    groups = [23, 24]
    grp_ext = _u16(10) + _u16(2 + len(groups) * 2) + _u16(len(groups) * 2) + b"".join(_u16(g) for g in groups)
    pf = bytes([0])
    pf_ext = _u16(11) + _u16(1 + len(pf)) + bytes([len(pf)]) + pf
    exts = sni_ext + grp_ext + pf_ext
    ciphers = [0x1301, 0x1302]
    body = (_u16(0x0303) + b"\x00" * 32 + b"\x00" + _u16(len(ciphers) * 2)
            + b"".join(_u16(c) for c in ciphers) + b"\x01\x00" + _u16(len(exts)) + exts)
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + _u16(len(handshake)) + handshake, handshake


def test_ja3_and_sni():
    record, handshake = _build_client_hello()
    res = tls.parse_client_hello(record)
    expected = "771,4865-4866,0-10-11,23-24,0"
    assert res["sni"] == "example.com"
    assert res["ja3"] == expected
    assert res["ja3_hash"] == hashlib.md5(expected.encode()).hexdigest()
    # also parses without the record header
    assert tls.parse_client_hello(handshake)["ja3"] == expected
