"""Authentication: login, refresh rotation, MFA enrolment, password change."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import Session, select

from app import audit
from app.config import get_settings
from app.db import get_session
from app.deps import (
    client_identity,
    current_user,
    find_user_by_email,
    login_limiter,
    user_email,
    user_out,
)
from app.models import Session as SessionRow
from app.models import User, utcnow
from app.schemas import ChangePasswordRequest, LoginRequest, RefreshRequest, TokenPair, UserOut
from app.security import mfa, passwords, tokens
from app.security.crypto import FieldContext, get_vault

router = APIRouter(prefix="/api/auth", tags=["auth"])

MAX_FAILED = 5
LOCKOUT_MINUTES = 15


def _issue(session: Session, user: User, request: Request, *, mfa_ok: bool,
           family_id: str | None = None) -> TokenPair:
    settings = get_settings()
    vault = get_vault()

    raw_refresh, digest = tokens.new_refresh_token()
    # A rotated token stays in its original family, so revoking the family on
    # replay kills every descendant — not just the one token that was reused.
    row = SessionRow(
        user_id=user.id, family_id=family_id or digest[:16], refresh_hash=digest,
        expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_ttl_days),
    )
    row.user_agent_sealed = vault.seal(
        request.headers.get("user-agent", "")[:400],
        FieldContext("sessions", "user_agent", row.id),
    )
    row.ip_sealed = vault.seal(
        client_identity(request), FieldContext("sessions", "ip", row.id)
    )
    session.add(row)

    access, expires = tokens.make_access_token(
        secret=settings.jwt_secret, subject=user.id, role=user.role,
        session_id=row.id, ttl_minutes=settings.access_ttl_min, mfa=mfa_ok,
    )
    user.last_login_at = utcnow()
    user.failed_logins = 0
    user.locked_until = None
    session.add(user)
    session.commit()

    return TokenPair(
        access_token=access, refresh_token=raw_refresh, expires_at=expires,
        role=user.role, mfa_required=False,
    )


@router.post("/login", response_model=TokenPair)
def login(body: LoginRequest, request: Request, session: Session = Depends(get_session)):
    identity = client_identity(request)
    allowed, retry = login_limiter.check(f"login:{identity}")
    if not allowed:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many login attempts",
                            headers={"Retry-After": str(int(retry) or 1)})

    user = find_user_by_email(session, body.email)
    # Constant-ish work whether or not the account exists.
    stored = user.password_hash if user else passwords.hash_password("decoy-value-x9")
    ok = passwords.verify_password(body.password, stored)

    if user is None or not ok:
        if user is not None:
            user.failed_logins += 1
            if user.failed_logins >= MAX_FAILED:
                user.locked_until = datetime.now(UTC) + timedelta(minutes=LOCKOUT_MINUTES)
                audit.record(session, action="auth.lockout", actor_id=user.id,
                             outcome="locked", detail={"ip": identity})
            session.add(user)
            session.commit()
        audit.record(session, action="auth.login", outcome="failure",
                     target=body.email, detail={"ip": identity})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    if user.locked_until and user.locked_until.replace(tzinfo=UTC) > datetime.now(UTC):
        raise HTTPException(status.HTTP_423_LOCKED, "account is temporarily locked")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "account disabled")

    mfa_ok = False
    if user.mfa_enabled:
        secret = get_vault().open(
            user.mfa_secret_sealed, FieldContext("users", "mfa_secret", user.id)
        )
        code = (body.totp or "").strip()
        if not code:
            audit.record(session, action="auth.mfa_required", actor_id=user.id)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "second factor required")
        if secret and mfa.verify_code(secret, code):
            mfa_ok = True
        else:
            digest = mfa.hash_recovery_code(code)
            remaining = [h for h in user.recovery_hashes.split("\n") if h]
            if digest in remaining:
                remaining.remove(digest)          # single use
                user.recovery_hashes = "\n".join(remaining)
                session.add(user)
                session.commit()
                mfa_ok = True
                audit.record(session, action="auth.recovery_code_used", actor_id=user.id)
        if not mfa_ok:
            audit.record(session, action="auth.mfa", actor_id=user.id, outcome="failure")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid second factor")

    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(body.password)

    audit.record(session, action="auth.login", actor_id=user.id, outcome="ok",
                 detail={"ip": identity, "mfa": mfa_ok})
    return _issue(session, user, request, mfa_ok=mfa_ok)


@router.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshRequest, request: Request, session: Session = Depends(get_session)):
    digest = tokens.hash_refresh_token(body.refresh_token)
    row = session.exec(select(SessionRow).where(SessionRow.refresh_hash == digest)).first()
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown refresh token")

    now = datetime.now(UTC)
    if row.revoked_at is not None:
        # Replay of a burned token: assume theft, drop the whole family.
        family = session.exec(
            select(SessionRow).where(SessionRow.family_id == row.family_id)
        ).all()
        for member in family:
            member.revoked_at = member.revoked_at or utcnow()
            session.add(member)
        session.commit()
        audit.record(session, action="auth.refresh_replay", actor_id=row.user_id,
                     outcome="revoked_family", target=row.family_id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "refresh token already used; session revoked")

    if row.expires_at.replace(tzinfo=UTC) < now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "refresh token expired")

    user = session.get(User, row.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account is not active")

    pair = _issue(session, user, request, mfa_ok=user.mfa_enabled,
                  family_id=row.family_id)
    row.revoked_at = utcnow()
    row.replaced_by = tokens.hash_refresh_token(pair.refresh_token)[:16]
    session.add(row)
    session.commit()
    audit.record(session, action="auth.refresh", actor_id=user.id)
    return pair


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: RefreshRequest, session: Session = Depends(get_session)):
    digest = tokens.hash_refresh_token(body.refresh_token)
    row = session.exec(select(SessionRow).where(SessionRow.refresh_hash == digest)).first()
    if row and row.revoked_at is None:
        row.revoked_at = utcnow()
        session.add(row)
        session.commit()
        audit.record(session, action="auth.logout", actor_id=row.user_id)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user_out(user)


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(body: ChangePasswordRequest, session: Session = Depends(get_session),
                    user: User = Depends(current_user)):
    if not passwords.verify_password(body.current_password, user.password_hash):
        audit.record(session, action="auth.password_change", actor_id=user.id,
                     outcome="failure")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "current password is wrong")
    try:
        passwords.check_policy(body.new_password, email=user_email(user))
    except passwords.WeakPassword as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    user.password_hash = passwords.hash_password(body.new_password)
    user.password_changed_at = utcnow()
    session.add(user)

    # Changing a password logs every other session out.
    for row in session.exec(select(SessionRow).where(SessionRow.user_id == user.id)).all():
        if row.revoked_at is None:
            row.revoked_at = utcnow()
            session.add(row)
    session.commit()
    audit.record(session, action="auth.password_change", actor_id=user.id)


@router.post("/mfa/enroll")
def mfa_enroll(session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Returns the TOTP URI and one-time recovery codes. Shown exactly once."""
    secret = mfa.new_secret()
    codes, digests = mfa.new_recovery_codes()
    vault = get_vault()
    user.mfa_secret_sealed = vault.seal(secret, FieldContext("users", "mfa_secret", user.id))
    user.recovery_hashes = "\n".join(digests)
    session.add(user)
    session.commit()
    audit.record(session, action="auth.mfa_enroll_start", actor_id=user.id)
    return {
        "provisioning_uri": mfa.provisioning_uri(secret, user_email(user)),
        "secret": secret,
        "recovery_codes": codes,
        "note": "Store these now. Recovery codes are shown once and each works once.",
    }


@router.post("/mfa/confirm", status_code=status.HTTP_204_NO_CONTENT)
def mfa_confirm(code: str, session: Session = Depends(get_session),
                user: User = Depends(current_user)):
    secret = get_vault().open(
        user.mfa_secret_sealed, FieldContext("users", "mfa_secret", user.id)
    )
    if not secret or not mfa.verify_code(secret, code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "code did not verify")
    user.mfa_enabled = True
    session.add(user)
    session.commit()
    audit.record(session, action="auth.mfa_enabled", actor_id=user.id)
