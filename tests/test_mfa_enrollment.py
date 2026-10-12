import pyotp


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
