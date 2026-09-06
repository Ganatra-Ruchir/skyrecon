"""Administration: users, audit trail, key rotation."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, col, select

from app import audit
from app.db import get_session
from app.deps import find_user_by_email, rate_limited, requires, user_out
from app.models import AuditEntry, User
from app.schemas import CreateUserRequest, UserOut
from app.security import passwords, rotation
from app.security.crypto import (
    FieldContext,
    Vault,
    generate_master_key,
    get_vault,
    reset_vault,
)
from app.security.rbac import Permission

router = APIRouter(prefix="/api/admin", tags=["admin"],
                   dependencies=[Depends(rate_limited)])


@router.get("/users", response_model=list[UserOut])
def list_users(session: Session = Depends(get_session),
               _: User = Depends(requires(Permission.USER_MANAGE))):
    return [user_out(u) for u in session.exec(select(User)).all()]


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: CreateUserRequest, session: Session = Depends(get_session),
                actor: User = Depends(requires(Permission.USER_MANAGE))):
    if find_user_by_email(session, body.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "that e-mail is already registered")
    try:
        passwords.check_policy(body.password, email=body.email)
    except passwords.WeakPassword as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    vault = get_vault()
    user = User(
        email_index=vault.blind_index(body.email, "user-email"),
        email_sealed="", password_hash=passwords.hash_password(body.password),
        role=body.role,
    )
    user.email_sealed = vault.seal(body.email, FieldContext("users", "email", user.id))
    if body.display_name:
        user.display_name_sealed = vault.seal(
            body.display_name, FieldContext("users", "display_name", user.id)
        )
    session.add(user)
    session.commit()
    session.refresh(user)
    audit.record(session, action="user.create", actor_id=actor.id, target=user.id,
                 detail={"role": body.role})
    return user_out(user)


@router.post("/users/{user_id}/role", response_model=UserOut)
def set_role(user_id: str, role: str, session: Session = Depends(get_session),
             actor: User = Depends(requires(Permission.USER_MANAGE))):
    if role not in {"viewer", "analyst", "admin"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown role")
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if user.id == actor.id and role != "admin":
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "refusing to remove your own admin role")
    before = user.role
    user.role = role
    session.add(user)
    session.commit()
    audit.record(session, action="user.role_change", actor_id=actor.id, target=user_id,
                 detail={"from": before, "to": role})
    return user_out(user)


@router.post("/users/{user_id}/disable", response_model=UserOut)
def disable_user(user_id: str, session: Session = Depends(get_session),
                 actor: User = Depends(requires(Permission.USER_MANAGE))):
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if user.id == actor.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "refusing to disable yourself")
    user.is_active = False
    session.add(user)
    session.commit()
    audit.record(session, action="user.disable", actor_id=actor.id, target=user_id)
    return user_out(user)


@router.get("/audit")
def read_audit(session: Session = Depends(get_session),
               _: User = Depends(requires(Permission.AUDIT_READ)),
               limit: int = 200):
    rows = session.exec(
        select(AuditEntry).order_by(col(AuditEntry.seq).desc()).limit(limit)
    ).all()
    intact, bad_seq = audit.verify_chain(session)
    return {
        "chain_intact": intact,
        "first_tampered_seq": bad_seq,
        "entries": [
            {"seq": r.seq, "at": r.at, "actor_id": r.actor_id, "action": r.action,
             "target": r.target, "outcome": r.outcome, "hash": r.entry_hash[:16]}
            for r in rows
        ],
    }


@router.get("/audit/verify")
def verify_audit(session: Session = Depends(get_session),
                 _: User = Depends(requires(Permission.AUDIT_READ))):
    intact, bad_seq = audit.verify_chain(session)
    return {"chain_intact": intact, "first_tampered_seq": bad_seq}


@router.post("/keys/rotate")
def rotate_keys(session: Session = Depends(get_session),
                actor: User = Depends(requires(Permission.KEY_ROTATE)),
                dry_run: bool = True):
    """
    Re-wrap every sealed field, and every blind index, under a freshly
    generated master key.

    The new key is returned exactly once and is never stored — set it in the
    environment and restart. With `dry_run=true` (the default) nothing is
    written and the response only sizes the operation.

    What gets rotated is declared in `app.security.rotation.PLAN`, and the test
    suite fails if a sealed column is missing from it. A partial rotation is
    worse than none: the fields left behind become unreadable the moment the
    old key is retired.
    """
    sizes = rotation.count_fields(session)
    planned = sum(sizes.values())

    if dry_run:
        return {
            "dry_run": True,
            "fields_to_rewrap": planned,
            "by_table": sizes,
            "warning": "Take a database backup before running with dry_run=false.",
        }

    old = get_vault()
    new_key = generate_master_key()
    new = Vault(new_key)

    try:
        touched = rotation.rotate(session, old, new)
        session.commit()
    except Exception as exc:
        # Never leave half the database under one key and half under another.
        session.rollback()
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "rotation aborted and rolled back; the existing key is still in use",
        ) from exc

    audit.record(session, action="key.rotate", actor_id=actor.id,
                 detail={"fields": touched, "by_table": sizes})
    reset_vault()
    return {
        "dry_run": False,
        "fields_rewrapped": touched,
        "by_table": sizes,
        "new_master_key": new_key,
        "action_required": "Set SKYRECON_MASTER_KEY to this value and restart. "
                           "It is shown once and never stored.",
    }
