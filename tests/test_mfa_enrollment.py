import pyotp
import pytest
from fastapi import HTTPException
from sqlmodel import Session, select

from app.db import get_engine
from app.models import User
from app.routers.auth import mfa_enroll


def test_enrollment_cannot_replace_enabled_mfa(client, auth):
    first = client.post("/api/auth/mfa/enroll", headers=auth)
    assert first.status_code == 200
    secret = first.json()["secret"]
    confirmed = client.post(
        "/api/auth/mfa/confirm", params={"code": pyotp.TOTP(secret).now()}, headers=auth
    )
    assert confirmed.status_code == 204
    replacement = client.post("/api/auth/mfa/enroll", headers=auth)
    assert replacement.status_code == 409
    login = client.post("/api/auth/login", json={
        "email": "admin@skyrecon.local", "password": "Bootstrap-Admin-2026!",
        "totp": pyotp.TOTP(secret).now(),
    })
    assert login.status_code == 200


def test_stale_enrollment_cannot_overwrite_concurrently_confirmed_secret(client, auth):
    enrolled = client.post("/api/auth/mfa/enroll", headers=auth).json()
    with Session(get_engine()) as session:
        stale_user = session.exec(select(User).where(User.role == "admin")).first()
        assert not stale_user.mfa_enabled
        confirmed = client.post("/api/auth/mfa/confirm", headers=auth,
                                params={"code": pyotp.TOTP(enrolled["secret"]).now()})
        assert confirmed.status_code == 204
        with pytest.raises(HTTPException) as error:
            mfa_enroll(session=session, user=stale_user)
        assert error.value.status_code == 409
