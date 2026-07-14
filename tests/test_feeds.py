"""Tests for netscope/security/feeds.py.

Tests only the PURE PARSER functions (parse_feed, parse_misp, parse_stix) with
synthetic input, and check_ip / check_domain / check_hash against indicators
loaded directly into the module-level sets.  No network calls.
"""
from netscope.security import feeds


def test_parse_feed_extracts_ips_from_plain_text():
    text = (
        "# abuse.ch style blocklist\n"
        "1.2.3.4\n"
        "5.6.7.8\t100\n"  # ipsum format: ip<TAB>count
        "; semi-colon comment\n"
        "not-an-ip\n"
        "\n"
    )
    ips, domains = feeds.parse_feed(text)
    assert "1.2.3.4" in ips
    assert "5.6.7.8" in ips
    assert not domains


def test_parse_feed_extracts_domains_and_skips_comments():
    text = (
        "# comment line\n"
        "evil.example.com\n"
        "bad-domain.net\n"
        "// another comment\n"
        "192.168.0.1\n"
    )
    ips, domains = feeds.parse_feed(text)
    assert "evil.example.com" in domains
    assert "bad-domain.net" in domains
    assert "192.168.0.1" in ips
    assert "# comment line" not in domains


def test_parse_misp_extracts_ips_domains_and_hashes():
    data = {
        "Attribute": [
            {"type": "ip-dst", "value": "10.20.30.40"},
            {"type": "ip-src", "value": "50.60.70.80"},
            {"type": "domain", "value": "Malware.Example.COM"},
            {"type": "hostname", "value": "c2.bad-host.org"},
            {"type": "sha256", "value": "a" * 64},
            {"type": "md5", "value": "b" * 32},
            {"type": "unknown", "value": "ignored"},
        ]
    }
    ips, domains, hashes = feeds.parse_misp(data)
    assert "10.20.30.40" in ips
    assert "50.60.70.80" in ips
    assert "malware.example.com" in domains
    assert "c2.bad-host.org" in domains
    assert "a" * 64 in hashes
    assert "b" * 32 in hashes


def test_parse_misp_handles_response_wrapper():
    data = {
        "response": {
            "Attribute": [
                {"type": "ip-dst", "value": "99.88.77.66"},
            ]
        }
    }
    ips, domains, hashes = feeds.parse_misp(data)
    assert "99.88.77.66" in ips


def test_parse_stix_extracts_from_indicator_patterns():
    sha = "c" * 64
    data = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": (
                    "[ipv4-addr:value = '203.0.113.1'] AND "
                    "[domain-name:value = 'stix.evil.net'] AND "
                    "[file:hashes.'SHA-256' = '" + sha + "']"
                ),
            },
            {"type": "malware"},  # non-indicator, should be skipped
        ],
    }
    ips, domains, hashes = feeds.parse_stix(data)
    assert "203.0.113.1" in ips
    assert "stix.evil.net" in domains
    assert sha in hashes


def test_check_ip_domain_hash_against_loaded_indicators():
    sentinel_ip = "9.9.9.200"
    sentinel_domain = "definitely-blocked-test.org"
    sentinel_hash = "f" * 64

    with feeds._lock:
        feeds._ips.add(sentinel_ip)
        feeds._domains.add(sentinel_domain)
        feeds._hashes.add(sentinel_hash)
    try:
        assert feeds.check_ip(sentinel_ip) is True
        assert feeds.check_ip("1.2.3.255") is False

        assert feeds.check_domain(sentinel_domain) is True
        # Parent-domain match: sub.definitely-blocked-test.org should also hit.
        assert feeds.check_domain("sub." + sentinel_domain) is True
        assert feeds.check_domain("totally-safe-domain.com") is False

        assert feeds.check_hash(sentinel_hash) is True
        assert feeds.check_hash("e" * 64) is False
    finally:
        with feeds._lock:
            feeds._ips.discard(sentinel_ip)
            feeds._domains.discard(sentinel_domain)
            feeds._hashes.discard(sentinel_hash)
