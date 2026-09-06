"""
Stateless access tokens, stateful refresh tokens.

Access tokens are short-lived JWTs carrying role and session id. Refresh tokens
are opaque, single-use and rotated: presenting one issues a new pair and burns
the old. Reusing a burned refresh token is treated as theft and kills the whole
session family.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import jwt

ALGORITHM = "HS256"
ISSUER = "skyrecon"


class TokenError(ValueError):
    """Invalid, expired or unusable token."""


def _now() -> datetime:
    return datetime.now(UTC)


def make_access_token(
    *, secret: str, subject: str, role: str, session_id: str, ttl_minutes: int,
    mfa: bool = False,
) -> tuple[str, datetime]:
    expires = _now() + timedelta(minutes=ttl_minutes)
    payload = {
        "iss": ISSUER,
        "sub": subject,
        "role": role,
        "sid": session_id,
        "mfa": mfa,
        "iat": int(_now().timestamp()),
        "nbf": int(_now().timestamp()),
        "exp": int(expires.timestamp()),
        "jti": secrets.token_urlsafe(12),
        "typ": "access",
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM), expires


def read_access_token(token: str, *, secret: str) -> dict:
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("token invalid") from exc
    if claims.get("typ") != "access":
        raise TokenError("wrong token type")
    return claims


def new_refresh_token() -> tuple[str, str]:
    """Returns (secret_to_send, digest_to_store). The raw value is never stored."""
    raw = secrets.token_urlsafe(48)
    return raw, hash_refresh_token(raw)


def hash_refresh_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()
