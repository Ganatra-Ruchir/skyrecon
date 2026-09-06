"""
Envelope encryption for data at rest.

Design
------
A single master key (from the environment, never the database) protects
per-record *data encryption keys* (DEKs). Each sensitive field is sealed with
its own DEK under AES-256-GCM, and the DEK itself is sealed under a key
derived from the master key. Consequences:

* Compromising the database alone yields no plaintext — the master key lives
  outside it.
* Rotating the master key rewraps DEKs only; ciphertext bodies stay untouched,
  so rotation is O(records) on tiny blobs instead of O(bytes) on everything.
* Every ciphertext carries an AAD binding it to its table, column and row id,
  so a stolen blob cannot be replayed into a different field or record.

Wire format (URL-safe base64, single string, stored in a normal TEXT column):

    v1.<wrapped_dek>.<nonce>.<ciphertext+tag>

Nothing here invents cryptography: it composes AES-GCM from `cryptography`
with HKDF-SHA256 for key separation.
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = "v1"
KEY_BYTES = 32          # AES-256
NONCE_BYTES = 12        # GCM standard nonce
_MIN_MASTER_BYTES = 32


class CryptoError(RuntimeError):
    """Raised when sealing or opening fails. Never leaks key material."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def generate_master_key() -> str:
    """A fresh master key, ready to paste into SKYRECON_MASTER_KEY."""
    return _b64e(secrets.token_bytes(KEY_BYTES))


@dataclass(frozen=True)
class FieldContext:
    """Binds a ciphertext to exactly one column of one row."""

    table: str
    column: str
    record_id: str = "*"

    def aad(self) -> bytes:
        return f"{VERSION}|{self.table}|{self.column}|{self.record_id}".encode()


class Vault:
    """Seals and opens field values under a master key."""

    def __init__(self, master_key: str) -> None:
        try:
            raw = _b64d(master_key)
        except Exception as exc:
            raise CryptoError("master key is not valid base64") from exc
        if len(raw) < _MIN_MASTER_BYTES:
            raise CryptoError(
                f"master key must be at least {_MIN_MASTER_BYTES} bytes, got {len(raw)}"
            )
        self._master = raw

    # -- key hierarchy ---------------------------------------------------
    def _kek(self, salt: bytes) -> bytes:
        """Key-encryption key derived per record, so DEKs never share a wrapper."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_BYTES,
            salt=salt,
            info=b"skyrecon/kek/v1",
        ).derive(self._master)

    # -- public API ------------------------------------------------------
    def seal(self, plaintext: str | bytes | None, ctx: FieldContext) -> str | None:
        """Encrypt one field value. ``None`` passes through untouched."""
        if plaintext is None:
            return None
        data = plaintext.encode() if isinstance(plaintext, str) else plaintext

        dek = secrets.token_bytes(KEY_BYTES)
        salt = secrets.token_bytes(16)
        wrapped = AESGCM(self._kek(salt)).encrypt(
            salt[:NONCE_BYTES], dek, b"skyrecon/dek/v1"
        )

        nonce = os.urandom(NONCE_BYTES)
        body = AESGCM(dek).encrypt(nonce, data, ctx.aad())

        return ".".join([VERSION, _b64e(salt + wrapped), _b64e(nonce), _b64e(body)])

    def open(self, sealed: str | None, ctx: FieldContext) -> str | None:
        """Decrypt one field value, verifying it belongs to this exact field."""
        if sealed is None:
            return None
        try:
            version, wrapped_b64, nonce_b64, body_b64 = sealed.split(".", 3)
        except ValueError as exc:
            raise CryptoError("ciphertext is malformed") from exc
        if version != VERSION:
            raise CryptoError(f"unsupported ciphertext version {version!r}")

        try:
            blob = _b64d(wrapped_b64)
            salt, wrapped = blob[:16], blob[16:]
            dek = AESGCM(self._kek(salt)).decrypt(
                salt[:NONCE_BYTES], wrapped, b"skyrecon/dek/v1"
            )
            plain = AESGCM(dek).decrypt(_b64d(nonce_b64), _b64d(body_b64), ctx.aad())
        except InvalidTag as exc:
            # Wrong key, tampered blob, or a ciphertext moved between fields.
            raise CryptoError("ciphertext failed authentication") from exc
        except Exception as exc:
            raise CryptoError("ciphertext could not be opened") from exc
        return plain.decode()

    def rewrap(self, sealed: str, ctx: FieldContext, new_master: str) -> str:
        """Re-encrypt a value under a new master key (key rotation)."""
        plain = self.open(sealed, ctx)
        return Vault(new_master).seal(plain, ctx)  # type: ignore[return-value]

    # -- deterministic index ---------------------------------------------
    def blind_index(self, value: str, domain: str) -> str:
        """
        Searchable, non-reversible fingerprint of an encrypted value.

        AES-GCM is randomised, so two encryptions of the same e-mail differ and
        cannot be looked up. This gives an equality-only index: a keyed hash
        that is stable for the same input but useless without the master key.
        Deliberately *not* usable for ordering or prefix search.
        """
        mac = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_BYTES,
            salt=domain.encode(),
            info=b"skyrecon/blind-index/v1",
        ).derive(self._master)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(mac + value.strip().lower().encode())
        return _b64e(digest.finalize())[:43]


_vault: Vault | None = None


def get_vault() -> Vault:
    """Process-wide vault, built from settings on first use."""
    global _vault
    if _vault is None:
        from app.config import get_settings

        _vault = Vault(get_settings().master_key)
    return _vault


def reset_vault() -> None:
    """Drop the cached vault (tests and key rotation)."""
    global _vault
    _vault = None
