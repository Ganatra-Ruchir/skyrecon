"""
Offline enrichment.

Every signal here is computed locally — no API keys, no outbound calls, works
in an air-gapped SOC. External providers plug in behind `Enricher` when the
network and budget allow.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field

from app.geoip import asn_facts, geo_facts
from app.models import IOCType

# Registrars and TLDs disproportionately represented in abuse reporting.
_RISKY_TLDS = {
    "tk": 0.9, "ml": 0.9, "ga": 0.9, "cf": 0.9, "gq": 0.9, "zip": 0.8, "mov": 0.8,
    "top": 0.7, "xyz": 0.6, "click": 0.7, "icu": 0.7, "cyou": 0.7, "rest": 0.6,
    "fit": 0.6, "su": 0.7, "pw": 0.6, "work": 0.5, "live": 0.4, "online": 0.5,
    "site": 0.5, "shop": 0.4, "info": 0.4, "biz": 0.4,
}

_SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "wallet", "invoice", "payment", "bank", "support", "recovery", "unlock",
)

_URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"}


def shannon_entropy(text: str) -> float:
    """Bits per character. Random-looking strings score high."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def consonant_ratio(text: str) -> float:
    letters = [c for c in text.lower() if c.isalpha()]
    if not letters:
        return 0.0
    vowels = sum(1 for c in letters if c in "aeiou")
    return 1 - (vowels / len(letters))


def dga_likelihood(domain: str) -> float:
    """
    0-1 estimate that a domain was machine-generated.

    Domain-generation algorithms produce high-entropy, vowel-poor labels with
    long digit runs. This is a heuristic, not a classifier verdict — it feeds
    the score, it does not decide alone.
    """
    label = domain.lower().split(".")[0]
    if len(label) < 6:
        return 0.0

    entropy = shannon_entropy(label)
    entropy_signal = max(0.0, min(1.0, (entropy - 2.8) / 1.4))
    consonants = max(0.0, min(1.0, (consonant_ratio(label) - 0.55) / 0.35))
    digits = sum(c.isdigit() for c in label) / len(label)
    digit_signal = min(1.0, digits * 2.2)
    length_signal = min(1.0, max(0.0, (len(label) - 10) / 14))
    # Pronounceable domains have vowel/consonant alternation; DGA output rarely does.
    runs = max((len(m.group(0)) for m in re.finditer(r"[bcdfghjklmnpqrstvwxz]+", label)),
               default=0)
    run_signal = min(1.0, max(0.0, (runs - 3) / 4))

    score = (entropy_signal * 0.34 + consonants * 0.2 + digit_signal * 0.16
             + length_signal * 0.15 + run_signal * 0.15)
    return round(min(1.0, score), 3)


def tld_risk(domain: str) -> float:
    parts = domain.lower().rstrip(".").split(".")
    return _RISKY_TLDS.get(parts[-1], 0.15) if len(parts) >= 2 else 0.15


def ip_facts(value: str) -> dict:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return {}
    return {
        "version": ip.version,
        "is_global": bool(ip.is_global),
        "is_private": bool(ip.is_private),
        "reverse_pointer": ip.reverse_pointer,
    }


@dataclass
class Enrichment:
    signals: dict = field(default_factory=dict)
    risk_modifier: float = 0.0          # -1..+1, nudges the base score
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "signals": self.signals,
            "risk_modifier": round(self.risk_modifier, 3),
            "reasons": self.reasons,
        }


def enrich(value: str, ioc_type: IOCType) -> Enrichment:
    out = Enrichment()
    v = value.lower()

    if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
        facts = ip_facts(value)
        out.signals.update(facts)
        if facts.get("is_global") is False:
            out.risk_modifier -= 0.4
            out.reasons.append("address is not globally routable")
        elif facts.get("is_global"):
            out.signals.update(geo_facts(value))
            out.signals.update(asn_facts(value))

    host = ""
    if ioc_type is IOCType.DOMAIN:
        host = v
    elif ioc_type is IOCType.URL:
        host = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0]
    elif ioc_type is IOCType.EMAIL:
        host = v.split("@")[-1]

    if host:
        dga = dga_likelihood(host)
        risk = tld_risk(host)
        entropy = round(shannon_entropy(host.split(".")[0]), 3)
        out.signals.update({"host": host, "dga_likelihood": dga,
                            "tld_risk": risk, "entropy": entropy,
                            "label_count": len(host.split("."))})
        if dga >= 0.55:
            out.risk_modifier += 0.30
            out.reasons.append(f"domain looks machine-generated (dga={dga})")
        if risk >= 0.6:
            out.risk_modifier += 0.20
            out.reasons.append(f"high-abuse TLD .{host.split('.')[-1]}")
        if host in _URL_SHORTENERS:
            out.risk_modifier += 0.10
            out.reasons.append("URL shortener hides the real destination")
        if len(host.split(".")) >= 5:
            out.risk_modifier += 0.10
            out.reasons.append("unusually deep subdomain chain")

    if ioc_type is IOCType.URL:
        hits = [w for w in _SUSPICIOUS_WORDS if w in v]
        if hits:
            out.risk_modifier += min(0.25, 0.08 * len(hits))
            out.reasons.append("credential-phishing keywords: " + ", ".join(hits[:4]))
        if re.search(r"\.(exe|scr|js|vbs|ps1|hta|jar|apk|dll|bat|cmd|zip|rar|7z)(\?|$)", v):
            out.risk_modifier += 0.25
            out.reasons.append("links directly to an executable payload")
        if re.match(r"^https?://\d{1,3}(\.\d{1,3}){3}", v):
            out.risk_modifier += 0.15
            out.reasons.append("bare IP address in place of a hostname")
        if v.startswith("http://"):
            out.risk_modifier += 0.05
            out.reasons.append("plaintext HTTP")

    out.risk_modifier = round(max(-1.0, min(1.0, out.risk_modifier)), 3)
    return out
