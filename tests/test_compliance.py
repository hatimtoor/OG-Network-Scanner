"""Tests for netscope/compliance.py.

Verifies that run() returns the expected structure and key fields, and that
html_report() produces a non-empty HTML string.  Does not assert specific
pass/fail outcomes because firewall/RDP status varies per machine.
"""
from netscope import compliance


def test_run_returns_all_required_top_level_keys():
    result = compliance.run()
    for key in ("generated", "controls", "passed", "total", "score"):
        assert key in result


def test_run_total_matches_controls_list_length():
    result = compliance.run()
    assert result["total"] == len(result["controls"])
    assert result["total"] > 0


def test_run_score_is_valid_percentage():
    result = compliance.run()
    assert isinstance(result["score"], (int, float))
    assert 0 <= result["score"] <= 100


def test_controls_each_have_required_fields():
    result = compliance.run()
    for control in result["controls"]:
        for field in ("id", "title", "framework", "status", "detail"):
            assert field in control, f"control {control.get('id')} missing field {field}"
        assert control["status"] in ("pass", "fail")


def test_html_report_returns_non_empty_html_string():
    html = compliance.html_report()
    assert isinstance(html, str)
    assert len(html) > 200
    assert "<table" in html
    assert "NetScope" in html
    assert "<!doctype html" in html
