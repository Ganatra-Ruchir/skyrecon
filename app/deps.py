"""Shared FastAPI dependencies: identity, permissions, rate limiting."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session, select

from app.config import get_settings
from app.db import get_session
from app.models import User
from app.security import tokens
from app.security.crypto import FieldContext, get_vault
from app.security.ratelimit import RateLimiter
from app.security.rbac import Permission, can

bearer = HTTPBearer(auto_error=False)
_settings = get_settings()
limiter = RateLimiter(capacity=_settings.rate_limit, window_seconds=_settings.rate_window)
login_limiter = RateLimiter(capacity=8, window_seconds=300)


def client_identity(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    ip = fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "?")
    return ip or "?"


def rate_limited(request: Request) -> None:
    allowed, retry_after = limiter.check(client_identity(request))
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="rate limit exceeded",
            headers={"Retry-After": str(max(1, int(retry_after)))},
        )


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    session: Session = Depends(get_session),
) -> User:
    if creds is None or not creds.credentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = tokens.read_access_token(creds.credentials, secret=get_settings().jwt_secret)
    except tokens.TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc),
                            headers={"WWW-Authenticate": "Bearer"}) from exc

    user = session.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account is not active")

    if user.locked_until and user.locked_until.replace(tzinfo=UTC) > datetime.now(UTC):
        raise HTTPException(status.HTTP_423_LOCKED, "account is temporarily locked")

    # A role change must invalidate tokens minted under the old role.
    if claims.get("role") != user.role:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "role changed, re-authenticate")

    if get_settings().require_admin_mfa and user.role == "admin" and user.mfa_enabled \
            and not claims.get("mfa"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "second factor required")
    return user


def requires(permission: Permission):
    """Dependency factory: `Depends(requires(Permission.IOC_WRITE))`."""

    def guard(user: User = Depends(current_user)) -> User:
        if not can(user.role, permission):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"role '{user.role}' lacks permission '{permission.value}'",
            )
        return user

    return guard


def user_email(user: User) -> str:
    return get_vault().open(user.email_sealed, FieldContext("users", "email", user.id)) or ""


def user_out(user: User) -> dict:
    vault = get_vault()
    return {
        "id": user.id,
        "email": user_email(user),
        "display_name": vault.open(
            user.display_name_sealed, FieldContext("users", "display_name", user.id)
        ),
        "role": user.role,
        "mfa_enabled": user.mfa_enabled,
        "is_active": user.is_active,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
    }


def find_user_by_email(session: Session, email: str) -> User | None:
    index = get_vault().blind_index(email, "user-email")
    return session.exec(select(User).where(User.email_index == index)).first()
