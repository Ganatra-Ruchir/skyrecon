"""
Confidence maths.

Threat intelligence rots. An indicator that was certainly malicious a year ago
is a coin flip today, so confidence decays on a half-life and every fresh
sighting pushes it back up. Everything here is pure and unit-tested.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime

from app.models import Severity

_SEVERITY_WEIGHT = {
    Severity.INFO: 0.2, Severity.LOW: 0.4, Severity.MEDIUM: 0.6,
    Severity.HIGH: 0.85, Severity.CRITICAL: 1.0,
}

# How much a source is trusted, 0-1. Unknown sources default to 0.5.
SOURCE_TRUST = {
    "manual": 0.9, "analyst": 0.9, "internal-sensor": 0.85,
    "partner-feed": 0.75, "osint": 0.55, "unknown": 0.5, "crowdsourced": 0.4,
}


def decayed_confidence(
    base: int, last_seen: datetime, *, half_life_days: int = 30,
    now: datetime | None = None, floor: int = 5,
) -> int:
    """Exponential decay: confidence halves every `half_life_days` of silence."""
    now = now or datetime.now(UTC)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    age_days = max(0.0, (now - last_seen).total_seconds() / 86400)
    if half_life_days <= 0:
        return int(base)
    decayed = base * math.pow(0.5, age_days / half_life_days)
    return max(floor, min(100, round(decayed)))


def reinforce(current: int, *, source: str = "unknown", hits: int = 1) -> int:
    """
    A new sighting raises confidence, with diminishing returns — repeated
    reports from a weak source should not reach certainty.
    """
    trust = SOURCE_TRUST.get(source, SOURCE_TRUST["unknown"])
    ceiling = 40 + trust * 60                      # 64 for OSINT, 94 for manual
    gain = (ceiling - current) * (1 - math.pow(0.72, max(1, hits)))
    return max(0, min(100, round(current + max(0.0, gain))))


def risk_score(
    *, confidence: int, severity: str, source: str = "unknown",
    corroborations: int = 0,
) -> float:
    """
    0-100 blend of how sure we are, how bad it would be, and how many
    independent sources agree. Used to rank alerts for a human queue.
    """
    try:
        weight = _SEVERITY_WEIGHT[Severity(severity)]
    except ValueError:
        weight = 0.6
    trust = SOURCE_TRUST.get(source, SOURCE_TRUST["unknown"])
    corroboration_bonus = 1 - math.pow(0.75, max(0, corroborations))
    raw = (confidence / 100) * 0.55 + weight * 0.30 + trust * 0.10 + corroboration_bonus * 0.05
    return round(min(100.0, max(0.0, raw * 100)), 1)


def severity_for(score: float) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 68:
        return Severity.HIGH
    if score >= 45:
        return Severity.MEDIUM
    if score >= 25:
        return Severity.LOW
    return Severity.INFO
