"""Password hashing, API keys, CSRF tokens."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

SCRYPT = dict(n=2**14, r=8, p=1, dklen=32)
API_KEY_PREFIX = "ags_"


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, **SCRYPT)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt_b64), **SCRYPT)
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except (ValueError, TypeError):
        return False


def new_api_key() -> tuple[str, str, str]:
    """Return (plaintext, prefix, sha256 hash). Only the hash is stored."""
    raw = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, raw[:12], hash_api_key(raw)


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def csrf_token(session: dict) -> str:
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(24)
        session["csrf"] = tok
    return tok


def check_csrf(session: dict, submitted: str | None) -> bool:
    tok = session.get("csrf")
    return bool(tok and submitted and hmac.compare_digest(tok, submitted))
