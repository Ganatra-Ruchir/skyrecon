"""TOTP second factor with single-use recovery codes."""

from __future__ import annotations

import hashlib
import secrets

import pyotp

ISSUER = "SkyRecon"
_DRIFT_WINDOWS = 1  # accept the neighbouring 30 s step for clock skew


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=ISSUER)


def verify_code(secret: str, code: str) -> bool:
    if not code or not code.strip().isdigit():
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=_DRIFT_WINDOWS)


def new_recovery_codes(count: int = 10) -> tuple[list[str], list[str]]:
    """Returns (codes_to_show_once, digests_to_store)."""
    codes = [
        f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}"
        for _ in range(count)
    ]
    return codes, [hash_recovery_code(c) for c in codes]


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode()).hexdigest()
