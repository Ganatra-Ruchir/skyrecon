"""
Recognize-only patterns for observable formats SkyRecon does not yet store or
enrich as full indicators (phone numbers, UPI IDs, IFSC codes, crypto
wallets, ASNs). Universal search uses this so it can label what it sees
honestly — "detected as X, no lookup available yet" — instead of either
silently ignoring the input or pretending to investigate it.

Keep this separate from app.ioc.parser.IOCType: those are types SkyRecon
actually stores, scores and enriches. Observables here are recognition
only, by design, until real backing functionality exists.
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("cert_fingerprint", re.compile(r"^(?:[a-f0-9]{2}:){19,31}[a-f0-9]{2}$", re.I)),
    ("asn", re.compile(r"^AS\d{1,10}$", re.I)),
    ("crypto_eth", re.compile(r"^0x[a-f0-9]{40}$", re.I)),
    ("crypto_btc", re.compile(r"^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,59})$")),
    ("ifsc", re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")),
    ("upi_id", re.compile(r"^[a-z0-9.\-_]{2,64}@[a-z]{2,20}$", re.I)),
    ("phone", re.compile(r"^\+?[1-9]\d{7,14}$")),
]

LABELS = {
    "cert_fingerprint": "certificate fingerprint",
    "asn": "ASN",
    "crypto_eth": "crypto wallet (Ethereum-style)",
    "crypto_btc": "crypto wallet (Bitcoin-style)",
    "ifsc": "IFSC code",
    "upi_id": "UPI ID",
    "phone": "phone number",
}


def detect_observable(value: str) -> str | None:
    """Best-effort format label, or None. Never called if parser.detect_type
    already matched — see app.services.universal_search."""
    v = value.strip()
    for key, rx in _PATTERNS:
        if rx.fullmatch(v):
            return key
    return None
