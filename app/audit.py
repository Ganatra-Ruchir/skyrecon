"""
Tamper-evident audit log.

Each entry stores the hash of the previous one, so the log forms a chain. An
attacker who edits or removes history has to rewrite every later entry, and
`verify_chain` detects it immediately.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlmodel import Session, select

from app.models import AuditEntry
from app.security.crypto import FieldContext, get_vault

GENESIS = "0" * 64


def canonical_ts(dt: datetime) -> str:
    """
    One string form for a timestamp, whatever the driver hands back.

    SQLite returns naive datetimes, Postgres returns aware ones. Hashing
    `isoformat()` directly meant the chain verified on write and failed on
    read — so the value is normalised to naive UTC, microsecond precision.
    """
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt.isoformat(timespec="microseconds")


def _digest(seq: int, at: str, actor: str, action: str, target: str,
            outcome: str, prev_hash: str) -> str:
    body = json.dumps(
        {"seq": seq, "at": at, "actor": actor, "action": action,
         "target": target, "outcome": outcome, "prev": prev_hash},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(body.encode()).hexdigest()


def record(
    session: Session, *, action: str, actor_id: str | None = None,
    target: str = "", outcome: str = "ok", detail: dict | None = None,
) -> AuditEntry:
    last = session.exec(
        select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)
    ).first()
    seq = (last.seq + 1) if last else 1
    prev_hash = last.entry_hash if last else GENESIS

    entry = AuditEntry(
        seq=seq, actor_id=actor_id, action=action, target=target,
        outcome=outcome, prev_hash=prev_hash, entry_hash="",
    )
    if detail:
        entry.detail_sealed = get_vault().seal(
            json.dumps(detail, sort_keys=True, default=str),
            FieldContext("audit_log", "detail", entry.id),
        )
    entry.entry_hash = _digest(
        seq, canonical_ts(entry.at), actor_id or "-", action, target, outcome, prev_hash
    )
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry


def verify_chain(session: Session) -> tuple[bool, int | None]:
    """Returns (intact, first_bad_seq)."""
    entries = session.exec(select(AuditEntry).order_by(AuditEntry.seq)).all()
    prev = GENESIS
    for e in entries:
        expected = _digest(
            e.seq, canonical_ts(e.at), e.actor_id or "-", e.action, e.target,
            e.outcome, prev,
        )
        if e.prev_hash != prev or e.entry_hash != expected:
            return False, e.seq
        prev = e.entry_hash
    return True, None
