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
import time
from pathlib import Path

from ..config import settings

_SECRET_FILE = Path(settings.db_path).resolve().parent / ".auth_secret"
_TOKEN_TTL = 7 * 86400  # seconds
_MEM_SECRET: bytes | None = None


def _secret() -> bytes:
    """Persisted signing secret. Fails *closed* — if the secret can't be stored,
    use a per-process random one (tokens won't survive a restart, but they can
    never be forged from a public constant)."""
    global _MEM_SECRET
    try:
        if _SECRET_FILE.exists():
            return _SECRET_FILE.read_bytes()
        s = secrets.token_bytes(32)
        _SECRET_FILE.write_bytes(s)
        return s
    except Exception:
        if _MEM_SECRET is None:
            _MEM_SECRET = secrets.token_bytes(32)
        return _MEM_SECRET


def create_token(role: str = "admin", ttl: int = _TOKEN_TTL) -> str:
    """Signed, expiring token: ``role.expiry.nonce.sig``."""
    exp = str(int(time.time()) + ttl)
    nonce = secrets.token_hex(8)
    payload = f"{role}.{exp}.{nonce}"
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_token(token: str) -> str | None:
    """Return the role if the token is valid and unexpired, else None."""
    if not token or token.count(".") != 3:
        return None
    role, exp, nonce, sig = token.split(".")
    payload = f"{role}.{exp}.{nonce}"
    expected = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        if int(exp) < int(time.time()):
            return None
    except ValueError:
        return None
    return role


def check_password(password: str) -> bool:
    if not settings.auth_password:
        return False
    return hmac.compare_digest(password or "", settings.auth_password)


def is_public(path: str) -> bool:
    """Paths reachable without auth: everything non-API, plus login/logout."""
    if path in ("/api/login", "/api/logout"):
        return True
    return not path.startswith("/api/")
