"""Tests for netscope/api/auth.py.

Covers: create_token/verify_token round-trip, tampered token rejection,
check_password with and without a configured password, and is_public path logic.
"""
from netscope.api.auth import create_token, verify_token, check_password, is_public


def test_create_token_and_verify_admin_role():
    token = create_token("admin")
    assert verify_token(token) == "admin"


def test_create_token_and_verify_custom_role():
    token = create_token("viewer")
    assert verify_token(token) == "viewer"


def test_verify_token_rejects_tampered_signature():
    token = create_token("admin")
    # Corrupt the last 4 characters of the signature.
    tampered = token[:-4] + "XXXX"
    assert verify_token(tampered) is None


def test_verify_token_rejects_empty_string():
    assert verify_token("") is None


def test_verify_token_rejects_token_without_dot():
    assert verify_token("nodothere") is None


def test_check_password_returns_false_when_no_password_configured(monkeypatch):
    from netscope.config import settings
    monkeypatch.setattr(settings, "auth_password", "")
    assert check_password("anything") is False
    assert check_password("") is False


def test_check_password_returns_true_for_correct_password(monkeypatch):
    from netscope.config import settings
    monkeypatch.setattr(settings, "auth_password", "hunter2secret")
    assert check_password("hunter2secret") is True


def test_check_password_returns_false_for_wrong_password(monkeypatch):
    from netscope.config import settings
    monkeypatch.setattr(settings, "auth_password", "hunter2secret")
    assert check_password("wrong") is False


def test_is_public_allows_login_and_logout_paths():
    assert is_public("/api/login") is True
    assert is_public("/api/logout") is True


def test_is_public_blocks_other_api_paths():
    assert is_public("/api/devices") is False
    assert is_public("/api/events") is False
    assert is_public("/api/cases") is False


def test_is_public_allows_non_api_static_paths():
    assert is_public("/") is True
    assert is_public("/index.html") is True
    assert is_public("/static/app.js") is True
