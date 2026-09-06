"""Role separation must hold at the API boundary, not just in the UI."""

import pytest


@pytest.fixture()
def viewer(client, auth):
    r = client.post("/api/admin/users", headers=auth, json={
        "email": "viewer@skyrecon.local", "password": "Correct-Horse-Battery-7!",
        "role": "viewer"})
    assert r.status_code == 201, r.text
    login = client.post("/api/auth/login", json={
        "email": "viewer@skyrecon.local", "password": "Correct-Horse-Battery-7!"})
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


@pytest.fixture()
def analyst(client, auth):
    client.post("/api/admin/users", headers=auth, json={
        "email": "analyst@skyrecon.local", "password": "Tumbling-Kettle-Drum-9!",
        "role": "analyst"})
    login = client.post("/api/auth/login", json={
        "email": "analyst@skyrecon.local", "password": "Tumbling-Kettle-Drum-9!"})
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_viewer_can_read_but_not_write(client, viewer):
    assert client.get("/api/indicators", headers=viewer).status_code == 200
    assert client.post("/api/indicators", headers=viewer,
                       json={"value": "185.220.101.7"}).status_code == 403


def test_viewer_cannot_reach_admin_surface(client, viewer):
    assert client.get("/api/admin/users", headers=viewer).status_code == 403
    assert client.get("/api/admin/audit", headers=viewer).status_code == 403
    assert client.post("/api/admin/keys/rotate", headers=viewer).status_code == 403


def test_analyst_can_write_iocs_but_not_manage_users(client, analyst):
    assert client.post("/api/indicators", headers=analyst,
                       json={"value": "91.219.236.22"}).status_code == 201
    assert client.get("/api/admin/users", headers=analyst).status_code == 403
    assert client.post("/api/rules", headers=analyst, json={
        "name": "analyst rule", "expression": "bytes_out > 1"}).status_code == 403


def test_password_policy_enforced_on_creation(client, auth):
    r = client.post("/api/admin/users", headers=auth, json={
        "email": "weak@skyrecon.local", "password": "password1234", "role": "viewer"})
    assert r.status_code == 422


def test_admin_cannot_demote_or_disable_themselves(client, auth):
    me = client.get("/api/auth/me", headers=auth).json()
    assert client.post(f"/api/admin/users/{me['id']}/role?role=viewer",
                       headers=auth).status_code == 400
    assert client.post(f"/api/admin/users/{me['id']}/disable",
                       headers=auth).status_code == 400


def test_refresh_token_rotation_and_replay_detection(client):
    login = client.post("/api/auth/login", json={
        "email": "admin@skyrecon.local", "password": "Bootstrap-Admin-2026!"}).json()
    first = login["refresh_token"]

    rotated = client.post("/api/auth/refresh", json={"refresh_token": first})
    assert rotated.status_code == 200
    assert rotated.json()["refresh_token"] != first

    replay = client.post("/api/auth/refresh", json={"refresh_token": first})
    assert replay.status_code == 401
    assert "revoked" in replay.json()["detail"].lower()

    # the whole family died with the replay
    stolen = client.post("/api/auth/refresh",
                         json={"refresh_token": rotated.json()["refresh_token"]})
    assert stolen.status_code == 401


def test_password_change_revokes_other_sessions(client, auth):
    r = client.post("/api/auth/password", headers=auth, json={
        "current_password": "Bootstrap-Admin-2026!",
        "new_password": "Quiet-Lantern-Harbour-4!"})
    assert r.status_code == 204
    old = client.post("/api/auth/login", json={
        "email": "admin@skyrecon.local", "password": "Bootstrap-Admin-2026!"})
    assert old.status_code == 401
    new = client.post("/api/auth/login", json={
        "email": "admin@skyrecon.local", "password": "Quiet-Lantern-Harbour-4!"})
    assert new.status_code == 200
