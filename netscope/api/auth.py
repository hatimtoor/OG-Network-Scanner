"""Optional authentication (R23).

Off by default (single-user local tool). When NETSCOPE_AUTH=true and a password
is set, the dashboard requires login: a signed cookie token gates the API. Roles
are supported in the token for future RBAC; today a correct password grants the
'admin' role. The signing secret is persisted so tokens survive restarts.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from pathlib import Path

from ..config import settings

_SECRET_FILE = Path(settings.db_path).resolve().parent / ".auth_secret"


def _secret() -> bytes:
    try:
        if _SECRET_FILE.exists():
            return _SECRET_FILE.read_bytes()
        s = secrets.token_bytes(32)
        _SECRET_FILE.write_bytes(s)
        return s
    except Exception:
        return b"netscope-fallback-secret"


def create_token(role: str = "admin") -> str:
    sig = hmac.new(_secret(), role.encode(), hashlib.sha256).hexdigest()
    return f"{role}.{sig}"


def verify_token(token: str) -> str | None:
    if not token or "." not in token:
        return None
    role, _, sig = token.partition(".")
    expected = hmac.new(_secret(), role.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected):
        return role
    return None


def check_password(password: str) -> bool:
    if not settings.auth_password:
        return False
    return hmac.compare_digest(password or "", settings.auth_password)


def is_public(path: str) -> bool:
    """Paths reachable without auth: everything non-API, plus login/logout."""
    if path in ("/api/login", "/api/logout"):
        return True
    return not path.startswith("/api/")
