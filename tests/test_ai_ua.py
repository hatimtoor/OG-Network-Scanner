"""Tests for netscope/enrich/useragent.py and netscope/ai/assistant.py.

useragent: parse() is a pure function -- test it directly with known UA strings.
assistant: test the rule-based FALLBACK path only.  The test environment has no
NETSCOPE_ANTHROPIC_KEY, so available() returns False and answer() always falls
through to _answer_fallback() without any network call.
"""
from netscope.enrich.useragent import parse


def test_ua_windows_chrome_identifies_correctly():
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    result = parse(ua)
    assert result["os"] == "Windows"
    assert result["browser"] == "Chrome"
    assert result["device_type"] == "computer"
    assert len(result["raw"]) > 0


def test_ua_iphone_safari_identifies_correctly():
    ua = (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.0 Mobile/15E148 Safari/604.1"
    )
    result = parse(ua)
    assert result["os"] == "iOS"
    assert result["browser"] == "Safari"
    assert result["device_type"] == "phone"


def test_ua_empty_string_returns_blank_fields():
    result = parse("")
    assert result["os"] == ""
    assert result["browser"] == ""
    assert result["device_type"] == ""
    assert result["raw"] == ""


def test_ua_android_mobile_chrome():
    ua = (
        "Mozilla/5.0 (Linux; Android 14; Pixel 7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Mobile Safari/537.36"
    )
    result = parse(ua)
    assert result["os"] == "Android"
    assert result["browser"] == "Chrome"
    assert result["device_type"] == "phone"


def test_ai_fallback_answers_device_count_question_without_network(monkeypatch):
    from netscope.config import settings
    from netscope.ai import assistant

    # Guarantee no API key so the fallback path is taken, not the LLM path.
    monkeypatch.setattr(settings, "anthropic_key", "")

    result = assistant.answer("how many devices are on the network?")
    assert result["source"] == "rules"
    assert isinstance(result["answer"], str)
    assert len(result["answer"]) > 0


def test_ai_fallback_answers_empty_question_with_prompt(monkeypatch):
    from netscope.config import settings
    from netscope.ai import assistant

    monkeypatch.setattr(settings, "anthropic_key", "")

    result = assistant.answer("")
    assert result["source"] == "none"
    assert "Ask" in result["answer"]


def test_ai_fallback_answers_alert_question_without_network(monkeypatch):
    from netscope.config import settings
    from netscope.ai import assistant

    monkeypatch.setattr(settings, "anthropic_key", "")

    result = assistant.answer("are there any critical alerts?")
    assert result["source"] == "rules"
    assert isinstance(result["answer"], str)
