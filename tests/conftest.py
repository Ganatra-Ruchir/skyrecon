import os

import pytest

os.environ.setdefault("SKYRECON_ENV", "test")
os.environ.setdefault("SKYRECON_REQUIRE_ADMIN_MFA", "false")
os.environ.setdefault("SKYRECON_BOOTSTRAP_PASSWORD", "Bootstrap-Admin-2026!")
os.environ.setdefault("SKYRECON_RATE_LIMIT", "10000")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A fresh app with an isolated database and freshly generated keys."""
    from app.security.crypto import generate_master_key

    db = tmp_path / "test.db"
    monkeypatch.setenv("SKYRECON_DATABASE_URL", f"sqlite:///{db}")
    monkeypatch.setenv("SKYRECON_MASTER_KEY", generate_master_key())
    monkeypatch.setenv("SKYRECON_JWT_SECRET", "x" * 48)

    from app.config import reset_settings
    from app.db import reset_engine
    from app.security.crypto import reset_vault

    reset_settings()
    reset_engine()
    reset_vault()

    import app.deps as deps
    deps.limiter.capacity = 100000
    deps.login_limiter.capacity = 100000
    deps.limiter.reset()
    deps.login_limiter.reset()

    from fastapi.testclient import TestClient

    from app.main import app as fastapi_app

    with TestClient(fastapi_app) as c:
        yield c

    reset_settings()
    reset_engine()
    reset_vault()


@pytest.fixture()
def admin_token(client):
    r = client.post("/api/auth/login", json={
        "email": "admin@skyrecon.local", "password": "Bootstrap-Admin-2026!"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture()
def auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}
