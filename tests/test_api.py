"""End-to-end API behaviour, including the security guarantees."""


def test_health_is_public(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_security_headers_present(client):
    h = client.get("/api/health").headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["referrer-policy"] == "no-referrer"


def test_protected_routes_require_a_token(client):
    for path in ("/api/indicators", "/api/alerts", "/api/admin/users", "/api/stats"):
        assert client.get(path).status_code == 401, path


def test_login_rejects_bad_credentials(client):
    r = client.post("/api/auth/login", json={
        "email": "admin@skyrecon.local", "password": "not-the-password"})
    assert r.status_code == 401
    assert "invalid" in r.json()["detail"].lower()


def test_login_and_me(client, auth):
    r = client.get("/api/auth/me", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "admin@skyrecon.local"
    assert body["role"] == "admin"


def test_indicator_lifecycle(client, auth):
    created = client.post("/api/indicators", headers=auth, json={
        "value": "hxxps://cdn-update[.]tk/payload.exe", "source": "manual",
        "severity": "high", "confidence": 80, "tags": ["c2", "dropper"]})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["value"] == "https://cdn-update.tk/payload.exe"
    assert body["ioc_type"] == "url"
    assert body["risk_score"] > 50
    assert body["enrichment"]["risk_modifier"] > 0
    assert "[.]" in body["defanged"]

    listed = client.get("/api/indicators", headers=auth)
    assert listed.status_code == 200
    assert any(i["id"] == body["id"] for i in listed.json())

    again = client.post("/api/indicators", headers=auth, json={
        "value": "https://cdn-update.tk/payload.exe", "source": "osint"})
    assert again.status_code == 201
    assert again.json()["id"] == body["id"], "duplicate must reinforce, not duplicate"
    assert again.json()["hit_count"] == 1


def test_indicator_rejects_noise(client, auth):
    for junk in ("192.168.0.5", "google.com", "not an indicator at all"):
        r = client.post("/api/indicators", headers=auth, json={"value": junk})
        assert r.status_code == 422, junk


def test_bulk_ingest_from_report(client, auth):
    r = client.post("/api/indicators/bulk", headers=auth, json={
        "text": "C2 at 91.219.236.18 and hxxp://malware-drop[.]xyz/a.exe; "
                "hash d41d8cd98f00b204e9800998ecf8427e; ignore 10.0.0.8 and github.com",
        "source": "report", "severity": "high", "tags": ["campaign-x"]})
    assert r.status_code == 200
    body = r.json()
    assert body["extracted"] >= 3
    assert len(body["created"]) >= 3
    assert not any("10.0.0.8" in v for v in body["created"])


def test_event_ingest_matches_indicator_and_raises_alert(client, auth):
    client.post("/api/indicators", headers=auth, json={
        "value": "185.220.101.44", "severity": "critical", "confidence": 90})

    r = client.post("/api/events", headers=auth, json={
        "source": "firewall", "kind": "netflow",
        "payload": "connection to 185.220.101.44 established",
        "bytes_out": 8_000_000, "bytes_in": 1200, "duration_ms": 500})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["matched_indicators"], "known indicator should match"
    assert body["alerts_created"], "a match must raise an alert"
    assert body["risk_score"] > 0

    alerts = client.get("/api/alerts", headers=auth).json()
    assert alerts
    top = alerts[0]
    assert top["severity"] in {"critical", "high", "medium"}
    assert isinstance(top["mitre"], list)


def test_alert_triage_flow(client, auth):
    client.post("/api/indicators", headers=auth, json={"value": "185.220.101.7"})
    client.post("/api/events", headers=auth, json={
        "source": "ids", "payload": "hit on 185.220.101.7"})
    alert_id = client.get("/api/alerts", headers=auth).json()[0]["id"]

    r = client.post(f"/api/alerts/{alert_id}/triage", headers=auth,
                    json={"state": "resolved", "note": "blocked at the edge"})
    assert r.status_code == 200
    assert r.json()["state"] == "resolved"
    assert r.json()["resolved_at"] is not None


def test_rule_creation_rejects_code_injection(client, auth):
    r = client.post("/api/rules", headers=auth, json={
        "name": "hostile", "expression": '__import__("os").system("id")'})
    assert r.status_code == 422
    assert "invalid rule" in r.json()["detail"].lower()


def test_builtin_rules_are_seeded(client, auth):
    rules = client.get("/api/rules", headers=auth).json()
    assert len(rules) >= 6
    assert all(r["expression"] for r in rules)


def test_exports(client, auth):
    client.post("/api/indicators", headers=auth, json={
        "value": "malicious-host.top", "confidence": 90, "severity": "high"})
    stix = client.get("/api/indicators/export/stix?min_confidence=10", headers=auth)
    assert stix.status_code == 200
    bundle = stix.json()
    assert bundle["type"] == "bundle"
    assert bundle["objects"][0]["pattern"].startswith("[domain-name:value")

    csv = client.get("/api/indicators/export/csv?min_confidence=10", headers=auth)
    assert csv.status_code == 200
    assert "malicious-host.top" in csv.text


def test_stats_shape(client, auth):
    s = client.get("/api/stats", headers=auth).json()
    for key in ("indicators", "alerts_open", "rules_enabled", "by_severity",
                "mitre_coverage", "top_indicators"):
        assert key in s


def test_audit_chain_is_intact_and_verifiable(client, auth):
    client.post("/api/indicators", headers=auth, json={"value": "91.219.236.31"})
    r = client.get("/api/admin/audit", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["chain_intact"] is True
    assert body["first_tampered_seq"] is None
    assert any(e["action"] == "ioc.create" for e in body["entries"])


def test_key_rotation_dry_run(client, auth):
    client.post("/api/indicators", headers=auth, json={"value": "45.155.205.44"})
    r = client.post("/api/admin/keys/rotate?dry_run=true", headers=auth)
    assert r.status_code == 200
    assert r.json()["dry_run"] is True
    assert r.json()["fields_to_rewrap"] > 0


def test_repeated_cause_is_counted_not_duplicated(client, auth):
    """A noisy sensor must not be able to flood the queue with identical alerts."""
    client.post("/api/indicators", headers=auth, json={
        "value": "185.220.101.99", "severity": "high", "confidence": 90})
    for _ in range(6):
        client.post("/api/events", headers=auth, json={
            "source": "ids", "payload": "repeat contact with 185.220.101.99"})

    alerts = client.get("/api/alerts", headers=auth).json()
    matching = [a for a in alerts if "185[.]220[.]101[.]99" in a["title"]]
    assert len(matching) == 1, "six identical detections should collapse into one alert"
    assert matching[0]["occurrences"] == 6


def test_encoded_powershell_rule_actually_fires(client, auth):
    r = client.post("/api/events", headers=auth, json={
        "source": "edr", "kind": "process",
        "payload": "powershell.exe -EncodedCommand JABzAD0ATgBlAHcALQBPAGIA"})
    assert r.status_code == 201
    assert r.json()["alerts_created"], "the built-in PowerShell rule must match"
    titles = [a["title"] for a in client.get("/api/alerts", headers=auth).json()]
    assert any("PowerShell" in t for t in titles)
