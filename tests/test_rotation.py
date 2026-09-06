"""
Key rotation must be complete, or it is worse than not rotating at all.

Two things are checked here: that the rotation plan covers every encrypted
surface the models actually declare, and that data written before a rotation is
still readable after one.
"""

from __future__ import annotations

import pytest
from sqlmodel import Session, select

from app.models import Alert, AuditEntry, Event, Indicator, User
from app.models import Session as UserSession
from app.security import rotation

TABLES = (User, Indicator, Event, Alert, UserSession, AuditEntry)


def test_plan_covers_every_encrypted_column():
    """A new *_sealed or *_index column must be added to the plan."""
    declared_sealed, declared_index = set(), set()
    for plan in rotation.PLAN:
        declared_sealed |= {(plan.model.__name__, c) for c in plan.sealed}
        declared_index |= {(plan.model.__name__, c) for c in plan.indexes}

    missing = []
    for model in TABLES:
        for column in model.model_fields:
            if column.endswith("_sealed") and (model.__name__, column) not in declared_sealed:
                missing.append(f"{model.__name__}.{column}")
            if column.endswith("_index") and (model.__name__, column) not in declared_index:
                missing.append(f"{model.__name__}.{column}")

    assert not missing, (
        "these encrypted columns are not in app.security.rotation.PLAN and would "
        f"become unreadable after a key rotation: {missing}"
    )


def test_every_planned_column_exists():
    """And the plan may not name a column that was renamed or removed."""
    for plan in rotation.PLAN:
        fields = set(plan.model.model_fields)
        for column in (*plan.sealed, *plan.indexes):
            assert column in fields, f"{plan.model.__name__}.{column} no longer exists"


def _readable_state(client, auth) -> dict:
    return {
        "indicators": sorted(
            i["value"] for i in client.get("/api/indicators", headers=auth).json()
        ),
        "alerts": sorted(a["title"] for a in client.get("/api/alerts", headers=auth).json()),
        "events": sorted(e["payload"] for e in client.get("/api/events", headers=auth).json()),
        "ips": sorted(
            (e.get("src_ip") or "") for e in client.get("/api/events", headers=auth).json()
        ),
        "me": client.get("/api/auth/me", headers=auth).json()["email"],
    }


def test_dry_run_changes_nothing(client, auth):
    client.post("/api/indicators",
                json={"value": "rotate-probe.example", "ioc_type": "domain",
                      "source": "manual", "severity": "medium"}, headers=auth)
    before = _readable_state(client, auth)

    r = client.post("/api/admin/keys/rotate?dry_run=true", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dry_run"] is True
    assert body["fields_to_rewrap"] > 0
    assert "new_master_key" not in body

    assert _readable_state(client, auth) == before


def test_everything_is_still_readable_after_rotation(client, auth, monkeypatch):
    # Data across every encrypted table.
    client.post("/api/indicators/bulk", json={
        "text": "C2 rendezvous domain: kqjxvbwzrtplmn[.]top from 45.155.205.233",
        "source": "report", "severity": "high",
    }, headers=auth)
    client.post("/api/events", json={
        "source": "dns", "kind": "dns", "payload": "query kqjxvbwzrtplmn.top A",
        "src_ip": "203.0.113.9", "dst_ip": "198.51.100.7",
        "bytes_out": 74, "bytes_in": 132, "duration_ms": 12,
    }, headers=auth)
    alerts = client.get("/api/alerts", headers=auth).json()
    assert alerts, "expected an alert to exist before rotating"
    client.post(f"/api/alerts/{alerts[0]['id']}/triage",
                json={"state": "triaged", "note": "checked before rotation"}, headers=auth)

    before = _readable_state(client, auth)
    assert before["indicators"] and before["alerts"] and before["events"]
    assert "203.0.113.9" in before["ips"]

    r = client.post("/api/admin/keys/rotate?dry_run=false", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["fields_rewrapped"] > 0
    new_key = body["new_master_key"]

    # The operator's next step: put the new key in the environment and restart.
    from app.config import reset_settings
    from app.security.crypto import reset_vault

    monkeypatch.setenv("SKYRECON_MASTER_KEY", new_key)
    reset_settings()
    reset_vault()

    after = _readable_state(client, auth)
    assert after == before, "a field did not survive rotation"

    # The new key opens the data; an unrelated key does not.
    from app.db import get_engine
    from app.security.crypto import CryptoError, FieldContext, Vault, generate_master_key

    with Session(get_engine()) as session:
        row = session.exec(select(Indicator)).first()
        ctx = FieldContext("indicators", "value", row.id)
        assert Vault(new_key).open(row.value_sealed, ctx)
        with pytest.raises(CryptoError):
            Vault(generate_master_key()).open(row.value_sealed, ctx)


def test_correlation_by_ip_survives_rotation(client, auth, monkeypatch):
    """The blind index is keyed by the master key, so it has to be rebuilt."""
    from app.db import get_engine
    from app.security.crypto import get_vault

    client.post("/api/events", json={
        "source": "netflow", "kind": "netflow", "payload": "session",
        "src_ip": "203.0.113.9", "bytes_out": 10, "bytes_in": 10, "duration_ms": 5,
    }, headers=auth)

    r = client.post("/api/admin/keys/rotate?dry_run=false", headers=auth)
    assert r.status_code == 200, r.text

    from app.config import reset_settings
    from app.security.crypto import reset_vault

    monkeypatch.setenv("SKYRECON_MASTER_KEY", r.json()["new_master_key"])
    reset_settings()
    reset_vault()

    wanted = get_vault().blind_index("203.0.113.9", "ip")
    with Session(get_engine()) as session:
        hits = session.exec(select(Event).where(Event.src_ip_index == wanted)).all()
    assert hits, "the source-IP index was not rebuilt under the new key"
