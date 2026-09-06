"""Database schema. Sensitive columns hold sealed blobs, never plaintext."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlmodel import Field, SQLModel


def _uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertState(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: str = Field(default_factory=_uuid, primary_key=True)
    email_index: str = Field(index=True, unique=True)   # blind index, not the address
    email_sealed: str                                    # AES-GCM ciphertext
    display_name_sealed: str | None = None
    password_hash: str
    role: str = Field(default="viewer", index=True)
    is_active: bool = True
    mfa_secret_sealed: str | None = None
    mfa_enabled: bool = False
    recovery_hashes: str = ""            # newline-joined sha256 digests
    failed_logins: int = 0
    locked_until: datetime | None = None
    last_login_at: datetime | None = None
    password_changed_at: datetime = Field(default_factory=utcnow)
    created_at: datetime = Field(default_factory=utcnow)


class Session(SQLModel, table=True):
    __tablename__ = "sessions"

    id: str = Field(default_factory=_uuid, primary_key=True)
    user_id: str = Field(index=True, foreign_key="users.id")
    family_id: str = Field(index=True)          # rotation chain
    refresh_hash: str = Field(index=True)
    user_agent_sealed: str | None = None
    ip_sealed: str | None = None
    issued_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    revoked_at: datetime | None = None
    replaced_by: str | None = None


class Indicator(SQLModel, table=True):
    __tablename__ = "indicators"

    id: str = Field(default_factory=_uuid, primary_key=True)
    value_index: str = Field(index=True, unique=True)   # blind index for dedupe
    value_sealed: str                                    # the indicator itself
    ioc_type: str = Field(index=True)
    source: str = Field(default="manual", index=True)
    confidence: int = Field(default=50, index=True)      # 0-100, decays with age
    severity: str = Field(default="medium", index=True)
    tags: str = ""                                       # comma-joined
    tlp: str = Field(default="amber")                    # traffic light protocol
    notes_sealed: str | None = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow, index=True)
    hit_count: int = 0
    is_active: bool = Field(default=True, index=True)
    created_by: str | None = Field(default=None, foreign_key="users.id")


class Event(SQLModel, table=True):
    """A raw observation submitted by a sensor, log shipper or analyst."""

    __tablename__ = "events"

    id: str = Field(default_factory=_uuid, primary_key=True)
    received_at: datetime = Field(default_factory=utcnow, index=True)
    source: str = Field(default="unknown", index=True)
    kind: str = Field(default="log", index=True)
    payload_sealed: str                       # full original record
    # Addresses are sealed *and* blind-indexed: the index makes correlation
    # possible without decrypting, the ciphertext keeps the value recoverable
    # for an analyst — and lets key rotation rebuild the index.
    src_ip_sealed: str | None = None
    dst_ip_sealed: str | None = None
    src_ip_index: str | None = Field(default=None, index=True)
    dst_ip_index: str | None = Field(default=None, index=True)
    bytes_out: int = 0
    bytes_in: int = 0
    duration_ms: int = 0
    risk_score: float = Field(default=0.0, index=True)


class Alert(SQLModel, table=True):
    __tablename__ = "alerts"

    id: str = Field(default_factory=_uuid, primary_key=True)
    created_at: datetime = Field(default_factory=utcnow, index=True)
    rule_id: str | None = Field(default=None, index=True)
    event_id: str | None = Field(default=None, foreign_key="events.id")
    indicator_id: str | None = Field(default=None, foreign_key="indicators.id")
    # An alert title quotes the indicator that caused it ("Known indicator
    # observed: kqjxvbwzrtplmn[.]top"), so it is exactly as sensitive as the
    # indicator itself and is sealed the same way.
    title_sealed: str
    severity: str = Field(default="medium", index=True)
    state: str = Field(default="open", index=True)
    score: float = 0.0
    # Keyed hash of (rule, indicator, title): equality-searchable for dedupe,
    # reveals nothing about the cause.
    dedupe_index: str = Field(default="", index=True)
    occurrences: int = 1
    last_seen_at: datetime = Field(default_factory=utcnow)
    mitre_techniques: str = ""            # comma-joined ATT&CK ids
    detail_sealed: str | None = None
    assigned_to: str | None = Field(default=None, foreign_key="users.id")
    resolved_at: datetime | None = None
    resolution_note_sealed: str | None = None


class DetectionRule(SQLModel, table=True):
    __tablename__ = "rules"

    id: str = Field(default_factory=_uuid, primary_key=True)
    name: str = Field(index=True, unique=True)
    description: str = ""
    enabled: bool = Field(default=True, index=True)
    severity: str = Field(default="medium")
    expression: str = ""                  # safe mini-DSL, see detect/rules.py
    mitre_techniques: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    hit_count: int = 0


class AuditEntry(SQLModel, table=True):
    """Append-only, hash-chained. Any edit or deletion breaks verification."""

    __tablename__ = "audit_log"

    id: str = Field(default_factory=_uuid, primary_key=True)
    seq: int = Field(index=True)
    at: datetime = Field(default_factory=utcnow, index=True)
    actor_id: str | None = Field(default=None, index=True)
    action: str = Field(index=True)
    target: str = ""
    outcome: str = "ok"
    detail_sealed: str | None = None
    prev_hash: str = ""
    entry_hash: str = Field(index=True)
