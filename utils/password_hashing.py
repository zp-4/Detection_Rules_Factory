"""PBKDF2 password hashing (stdlib only; no extra dependencies)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

SCHEME = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 390_000


def hash_password(plain: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    """Return a storable string: scheme$iterations$b64salt$b64digest."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", plain.encode("utf-8"), salt, iterations
    )
    return (
        f"{SCHEME}${iterations}$"
        f"{base64.b64encode(salt).decode('ascii')}$"
        f"{base64.b64encode(dk).decode('ascii')}"
    )


def verify_password(plain: str, stored: str) -> bool:
    """Constant-time compare of plain text against stored hash string."""
    if not stored or plain is None:
        return False
    plain = plain if isinstance(plain, str) else str(plain)
    try:
        parts = stored.split("$")
        if len(parts) != 4 or parts[0] != SCHEME:
            return False
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2])
        expected = base64.b64decode(parts[3])
        dk = hashlib.pbkdf2_hmac(
            "sha256", plain.encode("utf-8"), salt, iterations
        )
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False
