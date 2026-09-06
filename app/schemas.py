"""Request and response contracts. Validation happens here, not in handlers."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field, field_validator

from app.models import AlertState, IOCType, Severity

# Deliberately not `pydantic.EmailStr`: that rejects special-use domains, and an
# on-prem deployment legitimately uses admin@soc.local or ops@company.internal.
_EMAIL_RX = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,63}$")


def _valid_email(value: str) -> str:
    v = value.strip().lower()
    if not _EMAIL_RX.fullmatch(v) or ".." in v:
        raise ValueError("not a valid e-mail address")
    return v


EmailStr = Annotated[str, AfterValidator(_valid_email)]


# ── auth ────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=512)
    totp: str | None = Field(default=None, max_length=12)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth scheme name, not a secret
    expires_at: datetime
    role: str
    mfa_required: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=512)


class UserOut(BaseModel):
    id: str
    email: str
    display_name: str | None = None
    role: str
    mfa_enabled: bool
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime


class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=512)
    display_name: str | None = Field(default=None, max_length=120)
    role: str = "viewer"

    @field_validator("role")
    @classmethod
    def _known_role(cls, v: str) -> str:
        if v not in {"viewer", "analyst", "admin"}:
            raise ValueError("role must be viewer, analyst or admin")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=12, max_length=512)


# ── indicators ──────────────────────────────────────────────────────────
class IndicatorIn(BaseModel):
    value: str = Field(min_length=3, max_length=2048)
    ioc_type: IOCType | None = None
    source: str = Field(default="manual", max_length=64)
    severity: Severity = Severity.MEDIUM
    confidence: int = Field(default=50, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    tlp: str = Field(default="amber", pattern="^(clear|white|green|amber|red)$")
    notes: str | None = Field(default=None, max_length=4000)


class IndicatorOut(BaseModel):
    id: str
    value: str
    defanged: str
    ioc_type: str
    source: str
    severity: str
    confidence: int
    effective_confidence: int
    risk_score: float
    tags: list[str]
    tlp: str
    notes: str | None = None
    enrichment: dict | None = None
    first_seen: datetime
    last_seen: datetime
    hit_count: int
    is_active: bool


class BulkIngestRequest(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)
    source: str = Field(default="report", max_length=64)
    severity: Severity = Severity.MEDIUM
    tags: list[str] = Field(default_factory=list)


# ── events & alerts ─────────────────────────────────────────────────────
class EventIn(BaseModel):
    source: str = Field(default="sensor", max_length=64)
    kind: str = Field(default="log", max_length=32)
    payload: str = Field(min_length=1, max_length=64_000)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    bytes_out: int = Field(default=0, ge=0)
    bytes_in: int = Field(default=0, ge=0)
    duration_ms: int = Field(default=0, ge=0)


class EventOut(BaseModel):
    id: str
    received_at: datetime
    source: str
    kind: str
    payload: str
    src_ip: str | None = None
    dst_ip: str | None = None
    bytes_out: int = 0
    bytes_in: int = 0
    duration_ms: int = 0
    risk_score: float
    matched_indicators: list[str] = Field(default_factory=list)
    alerts_created: list[str] = Field(default_factory=list)
    anomaly: float | None = None
    anomaly_reasons: list[str] = Field(default_factory=list)


class AlertOut(BaseModel):
    id: str
    created_at: datetime
    title: str
    occurrences: int = 1
    severity: str
    state: str
    score: float
    rule_id: str | None = None
    event_id: str | None = None
    indicator_id: str | None = None
    mitre: list[dict] = Field(default_factory=list)
    detail: dict | None = None
    assigned_to: str | None = None
    resolved_at: datetime | None = None


class TriageRequest(BaseModel):
    state: AlertState
    note: str | None = Field(default=None, max_length=2000)


# ── rules ───────────────────────────────────────────────────────────────
class RuleIn(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=1000)
    expression: str = Field(min_length=1, max_length=2000)
    severity: Severity = Severity.MEDIUM
    mitre_techniques: list[str] = Field(default_factory=list)
    enabled: bool = True


class RuleOut(BaseModel):
    id: str
    name: str
    description: str
    expression: str
    severity: str
    enabled: bool
    mitre: list[dict] = Field(default_factory=list)
    hit_count: int
    created_at: datetime
    updated_at: datetime
