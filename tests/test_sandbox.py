"""Tests for netscope/security/sandbox.py pure parsers.

Tests parse_cuckoo_report and parse_vt_verdicts with synthetic dict input.
No network calls, no file I/O, no Cuckoo/VirusTotal API.
"""
from netscope.security.sandbox import parse_cuckoo_report, parse_vt_verdicts


def test_parse_cuckoo_report_extracts_score_and_signatures():
    report = {
        "info": {"score": 7.5},
        "signatures": [
            {"name": "network_cnc_http"},
            {"name": "ransomware_files"},
            {"name": ""},          # empty name must be excluded
            {"other_key": "val"},  # missing 'name' must be excluded
        ],
    }
    score, sigs = parse_cuckoo_report(report)
    assert score == 7.5
    assert "network_cnc_http" in sigs
    assert "ransomware_files" in sigs
    assert "" not in sigs


def test_parse_cuckoo_report_returns_zero_score_for_empty_report():
    score, sigs = parse_cuckoo_report({})
    assert score == 0.0
    assert sigs == []


def test_parse_cuckoo_report_handles_zero_score_explicitly():
    report = {"info": {"score": 0}, "signatures": []}
    score, sigs = parse_cuckoo_report(report)
    assert score == 0.0
    assert sigs == []


def test_parse_vt_verdicts_malicious_when_sandbox_says_malicious():
    data = {
        "data": {
            "attributes": {
                "sandbox_verdicts": {
                    "Sandbox_A": {
                        "category": "malicious",
                        "malware_classification": ["Trojan", "Dropper"],
                    },
                    "Sandbox_B": {
                        "category": "clean",
                        "malware_classification": [],
                    },
                },
                "last_analysis_stats": {"malicious": 3, "harmless": 20},
            }
        }
    }
    verdict, tags = parse_vt_verdicts(data)
    assert verdict == "malicious"
    assert "Trojan" in tags
    assert "Dropper" in tags


def test_parse_vt_verdicts_clean_when_all_sandboxes_clean():
    data = {
        "attributes": {
            "sandbox_verdicts": {
                "CleanBox": {"category": "clean", "malware_classification": []}
            },
            "last_analysis_stats": {"malicious": 0, "harmless": 60},
        }
    }
    verdict, tags = parse_vt_verdicts(data)
    assert verdict == "clean"
    assert tags == []


def test_parse_vt_verdicts_malicious_from_analysis_stats_alone():
    data = {
        "data": {
            "attributes": {
                "sandbox_verdicts": {},
                "last_analysis_stats": {"malicious": 5, "harmless": 10},
            }
        }
    }
    verdict, tags = parse_vt_verdicts(data)
    assert verdict == "malicious"


def test_parse_vt_verdicts_unknown_when_no_data():
    verdict, tags = parse_vt_verdicts({})
    assert verdict == "unknown"
    assert tags == []
