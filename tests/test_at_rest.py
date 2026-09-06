"""
Nothing sensitive may be recoverable from the database files themselves.

This is the test that catches the mistake that is easy to make: a field is
encrypted, and then some *derived* value — an alert title quoting the
indicator, a dedupe key built from that title, a log line — writes the same
secret back in the clear. Encrypting the obvious column is not the same as
protecting the data.

The check reads the raw bytes an attacker would walk away with, main database
and write-ahead log both, rather than querying through the ORM.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Every one of these is fed in through the API below and must not survive
# anywhere in the files afterwards.
SECRETS = {
    "indicator value": "kqjxvbwzrtplmn.top",
    "indicator value, defanged": "kqjxvbwzrtplmn[.]top",
    "c2 address": "45.155.205.233",
    "event payload": "EncodedCommand",
    "operator mailbox": "payments@invoice-desk.ru",
    "analyst e-mail": "atrest-probe@soc.example",
    "admin password": "Bootstrap-Admin-2026!",
    "triage note": "contained-by-night-shift",
}

REPORT = """
Beacon to hxxp://45.155.205.233/gate.php from the compromised host.
C2 rendezvous domain: kqjxvbwzrtplmn[.]top
Operator mailbox: payments[at]invoice-desk[dot]ru
"""


def _db_bytes(db_path: Path) -> bytes:
    """Main file plus WAL and shared-memory sidecars, as they sit on disk."""
    blob = b""
    for suffix in ("", "-wal", "-shm", "-journal"):
        p = Path(str(db_path) + suffix)
        if p.exists():
            blob += p.read_bytes()
    return blob


@pytest.fixture()
def db_path(tmp_path) -> Path:
    return tmp_path / "test.db"


def test_no_plaintext_survives_in_the_database_files(client, auth, tmp_path):
    # 1. an indicator, its alert, an event, a user and a triage note
    r = client.post("/api/indicators/bulk",
                    json={"text": REPORT, "source": "report", "severity": "high"},
                    headers=auth)
    assert r.status_code == 200, r.text
    assert r.json()["extracted"] >= 3

    r = client.post("/api/events", json={
        "source": "edr", "kind": "process",
        "payload": "powershell.exe -EncodedCommand JABzAD0ATgBl",
        "src_ip": "10.4.2.19", "bytes_out": 0, "bytes_in": 0, "duration_ms": 90,
    }, headers=auth)
    assert r.status_code == 201, r.text

    r = client.post("/api/events", json={
        "source": "dns", "kind": "dns", "payload": "query kqjxvbwzrtplmn.top A",
        "bytes_out": 74, "bytes_in": 132, "duration_ms": 12,
    }, headers=auth)
    assert r.status_code == 201, r.text
    alerts = client.get("/api/alerts", headers=auth).json()
    assert alerts, "expected the indicator hit to raise an alert"

    # the alert title must quote the indicator when read back through the API…
    assert any("kqjxvbwzrtplmn" in a["title"] for a in alerts), \
        "the title should still be readable to an authorised analyst"

    r = client.post(f"/api/alerts/{alerts[0]['id']}/triage",
                    json={"state": "triaged", "note": "contained-by-night-shift"},
                    headers=auth)
    assert r.status_code == 200, r.text

    r = client.post("/api/admin/users", json={
        "email": "atrest-probe@soc.example", "password": "Probe-Passphrase-2026!",
        "role": "analyst",
    }, headers=auth)
    assert r.status_code == 201, r.text

    # 2. …and must be unrecoverable from the files on disk
    blob = _db_bytes(tmp_path / "test.db")
    assert blob, "no database file was written"

    leaked = [
        label for label, secret in SECRETS.items()
        if secret.encode() in blob or secret.encode("utf-16-le") in blob
    ]
    assert not leaked, f"plaintext recoverable from the database files: {leaked}"


def test_password_hashes_are_argon2id(client, auth, tmp_path):
    client.get("/api/auth/me", headers=auth)
    blob = _db_bytes(tmp_path / "test.db")
    assert b"$argon2id$" in blob, "expected Argon2id password hashes on disk"
    assert b"$2b$" not in blob and b"sha1$" not in blob


def test_blind_indexes_do_not_reveal_their_input(client, auth, tmp_path):
    client.post("/api/admin/users", json={
        "email": "atrest-probe@soc.example", "password": "Probe-Passphrase-2026!",
        "role": "viewer",
    }, headers=auth)
    blob = _db_bytes(tmp_path / "test.db")
    for fragment in (b"atrest-probe", b"soc.example"):
        assert fragment not in blob, f"{fragment!r} leaked through an index"
