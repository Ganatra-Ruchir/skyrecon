import json
from datetime import UTC, datetime, timedelta

import pytest

from app.assessment import assess, collect, phone_lookup, target_url
from tools.import_cve_catalog import import_feed


@pytest.mark.parametrize("url", ["http://example.com", "https://user:pass@example.com", "https://example.com:444", "https://example.com/?token=secret", "https://example.com/\r\nx:y"])
def test_bad_targets(url):
    with pytest.raises(ValueError):
        target_url(url)


def test_default_deny(monkeypatch):
    monkeypatch.delenv("SKYRECON_SCAN_HOSTS", raising=False)
    with pytest.raises(ValueError, match="allowlist"):
        collect("https://example.com")


def test_private_dns_denied(monkeypatch):
    monkeypatch.setenv("SKYRECON_SCAN_HOSTS", "example.com")
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(ValueError, match="DNS"):
        collect("https://example.com")


def test_observations_never_certify_safety():
    r = assess({"url": "https://example.com", "headers": {}, "status": 302})
    assert "Insufficient" in r["verdict"]
    assert r["coverage"]["incomplete_response"]
    assert len(r["evidence_sha256"]) == 64
    assert any(x["id"] == "framing" for x in r["findings"])


def test_csp_directive_not_substring():
    r = assess({"url": "https://example.com", "headers": {"content-security-policy": "report-uri /frame-ancestors"}})
    assert any(x["id"] == "framing" for x in r["findings"])


def test_phone_unknown_and_expired(monkeypatch, tmp_path):
    directory = tmp_path / "business.json"
    directory.write_text(json.dumps({"+442079460000": {"kind": "public_business", "name": "Test fixture", "source_url": "https://example.com", "verified_at": (datetime.now(UTC)-timedelta(days=91)).isoformat()}}))
    monkeypatch.setenv("SKYRECON_BUSINESS_DIRECTORY", str(directory))
    assert phone_lookup("+44 20 7946 0000")["owner"] == "Owner unknown"
    with pytest.raises(ValueError):
        phone_lookup("local123")


def test_no_identity_invention(monkeypatch):
    monkeypatch.delenv("SKYRECON_BUSINESS_DIRECTORY", raising=False)
    result = phone_lookup("+12025550123")
    assert result["owner"] == "Owner unknown"
    assert result["source"] is None


def test_catalogue_deduplicates(tmp_path):
    import sqlite3
    source, db = tmp_path / "feed.json", tmp_path / "cve.sqlite"
    source.write_text(json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2024-12345", "descriptions": [{"lang": "en", "value": "fixture"}]}}, {"cve": {"id": "CVE-2023-12345"}}]}))
    assert import_feed(source, db) == 1
    import_feed(source, db)
    with sqlite3.connect(db) as c:
        assert c.execute("SELECT count(*) FROM cves").fetchone()[0] == 1


def test_api_requires_auth(client):
    assert client.post("/api/assessment/evidence", json={"url": "https://example.com"}).status_code == 401


def test_api_audit_and_default_denial(client, auth, monkeypatch):
    monkeypatch.delenv("SKYRECON_SCAN_HOSTS", raising=False)
    assert client.post("/api/assessment/evidence", headers=auth, json={"url": "https://example.com"}).status_code == 200
    assert client.post("/api/assessment/scan", headers=auth, json={"url": "https://example.com", "authorization_reference": "LOCAL-TEST-ONLY"}).status_code == 422
    assert client.post("/api/assessment/phone", headers=auth, json={"number": "+12025550123"}).json()["owner"] == "Owner unknown"
