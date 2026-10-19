import json

import pytest

from app.native_reports import normalize


def zap():
    return {"@version": "fixture", "site": [{"@name": "https://example.com", "alerts": [{"pluginid": "10038", "alert": "Fixture policy warning", "riskcode": "1", "confidence": "2", "desc": "<script>fixture</script>", "instances": [{"uri": "https://example.com/", "evidence": "SECRET", "request-header": "SECRET"}]}]}]}


def trivy():
    return {"SchemaVersion": 2, "Results": [{"Target": "fixture-image", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0000", "PkgName": "fixture", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"}], "Secrets": [{"Match": "SECRET"}]}]}


def test_zap_preserves_risk_locations_but_not_request_secrets():
    report = normalize(zap(), "zap")
    finding = report["findings"][0]
    assert finding["severity"] == "low"
    assert finding["confidence"] == "2"
    assert finding["locations"] == ["https://example.com/"]
    assert "SECRET" not in json.dumps(report)


def test_trivy_versions_and_omissions():
    data = trivy()
    data["Results"][0]["Vulnerabilities"] *= 2
    report = normalize(data, "trivy")
    assert report["coverage"]["duplicates_removed"] == 1
    assert report["coverage"]["omitted_non_vulnerability_records"] == 1
    assert report["findings"][0]["fixed_version"] == "2"
    assert "SECRET" not in json.dumps(report)


@pytest.mark.parametrize("kind,data", [("zap", {}), ("trivy", {"SchemaVersion": 1}), ("trivy", {"SchemaVersion": 2, "Results": {}}), ("zap", []), ("other", {})])
def test_malformed_reports_rejected(client, auth, kind, data):
    assert client.post("/api/assessment/tool-report", headers=auth, json={"format": kind, "report_json": json.dumps(data)}).status_code == 422


def test_limit_and_empty_reports():
    data = trivy()
    data["Results"][0]["Vulnerabilities"] *= 1001
    with pytest.raises(ValueError):
        normalize(data, "trivy")
    report = normalize({"SchemaVersion": 2, "Results": []}, "trivy")
    assert "do not prove" in report["limitations"]


def test_auth_and_success(client, auth):
    body = {"format": "zap", "report_json": json.dumps(zap())}
    assert client.post("/api/assessment/tool-report", json=body).status_code == 401
    assert client.post("/api/assessment/tool-report", headers=auth, json=body).status_code == 200
