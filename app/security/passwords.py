"""Password hashing (Argon2id) and policy."""

from __future__ import annotations

import re
import unicodedata

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# Tuned for an interactive login on modest hardware: ~64 MiB, ~0.1 s.
_hasher = PasswordHasher(
    time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16, type=Type.ID
)

MIN_LENGTH = 12
_COMMON = {
    "password", "passw0rd", "123456789012", "qwertyuiop12", "letmein12345",
    "administrator", "skyrecon1234", "changeme1234",
}


class WeakPassword(ValueError):
    """Raised when a candidate password fails policy."""


def normalize(password: str) -> str:
    """NFKC so visually identical passwords compare equal across platforms."""
    return unicodedata.normalize("NFKC", password)


def check_policy(password: str, *, email: str | None = None) -> None:
    pw = normalize(password)
    if len(pw) < MIN_LENGTH:
        raise WeakPassword(f"password must be at least {MIN_LENGTH} characters")
    if pw.lower() in _COMMON:
        raise WeakPassword("password appears in the common-password list")
    classes = sum(
        bool(rx.search(pw))
        for rx in (re.compile(r"[a-z]"), re.compile(r"[A-Z]"),
                   re.compile(r"\d"), re.compile(r"[^\w\s]"))
    )
    if classes < 3:
        raise WeakPassword(
            "use at least three of: lowercase, uppercase, digits, symbols"
        )
    if email:
        local = email.split("@")[0].lower()
        if len(local) >= 4 and local in pw.lower():
            raise WeakPassword("password must not contain your e-mail address")
    if re.search(r"(.)\1{3,}", pw):
        raise WeakPassword("password must not repeat a character four times in a row")


def hash_password(password: str) -> str:
    return _hasher.hash(normalize(password))


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return _hasher.verify(stored_hash, normalize(password))
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True when parameters have moved on and the hash should be upgraded."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except Exception:
        return True
