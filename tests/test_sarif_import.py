import json

import pytest

from app.sarif_import import normalize


def fixture():
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Fixture tool", "version": "1"}},
            "results": [{"ruleId": "test-rule", "level": "error", "message": {"text": "<script>fixture</script>"},
                         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///not-read"}, "region": {"startLine": 3}}}]}]}]}


def test_dedup_preserves_unverified_origin_and_location():
    data = fixture()
    data["runs"][0]["results"] *= 2
    result = normalize(data)
    assert result["coverage"] == {"input_results": 2, "unique_findings": 1, "duplicates_removed": 1}
    assert result["findings"][0]["locations"][0]["line"] == 3
    assert result["findings"][0]["evidence"] == "<script>fixture</script>"
    assert result["findings"][0]["severity"] == "tool level: error"
    assert "not authenticated" in result["source"][0]["provenance"]


def test_external_files_and_large_result_sets_rejected():
    data = fixture()
    data["runs"][0]["externalPropertyFileReferences"] = {"results": [{"location": {"uri": "https://example.com"}}]}
    with pytest.raises(ValueError, match="External"):
        normalize(data)
    data = fixture()
    data["runs"][0]["results"] *= 1001
    with pytest.raises(ValueError, match="1000"):
        normalize(data)


@pytest.mark.parametrize("data", [{}, [], {"version": "2.1.0", "runs": [None]}, {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": [{"message": {"id": "unresolved"}}]}]}])
def test_bad_import_is_validation_error(client, auth, data):
    assert client.post("/api/assessment/sarif", headers=auth, json={"report_json": json.dumps(data)}).status_code == 422


def test_import_permissions(client, auth):
    body = {"report_json": json.dumps(fixture())}
    assert client.post("/api/assessment/sarif", json=body).status_code == 401
    assert client.post("/api/assessment/sarif", headers=auth, json=body).status_code == 200
    client.post("/api/admin/users", headers=auth, json={"email": "report-viewer@skyrecon.local", "password": "Fixture-Password-Only-42!", "role": "viewer"})
    login = client.post("/api/auth/login", json={"email": "report-viewer@skyrecon.local", "password": "Fixture-Password-Only-42!"}).json()
    viewer = {"Authorization": "Bearer " + login["access_token"]}
    assert client.post("/api/assessment/sarif", headers=viewer, json=body).status_code == 403
    assert client.post("/api/assessment/scan", headers=viewer, json={"url": "https://example.com", "authorization_reference": "test-only"}).status_code == 403
