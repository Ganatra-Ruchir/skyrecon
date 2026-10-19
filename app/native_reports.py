"""Bounded native report readers. Never run scanners or retrieve report resources."""
import hashlib
import json
from datetime import UTC, datetime


def text(value, limit=4096):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError("Invalid or oversized text field")
    return value


def items(value, limit=1000):
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("Invalid or oversized array")
    return value


def normalize(document: dict, kind: str) -> dict:
    findings = []
    omitted = 0
    version = "unspecified"
    if kind == "zap":
        version = text(document["@version"], 200)
        for site in items(document["site"], 100):
            target = text(site["@name"], 2048)
            for alert in items(site["alerts"]):
                risk = str(alert["riskcode"])
                if risk not in ("0", "1", "2", "3"):
                    raise ValueError("Invalid ZAP risk code")
                instances = items(alert.get("instances", []))
                findings.append({"title": text(alert["alert"], 300), "rule_id": text(str(alert["pluginid"]), 200),
                                 "severity": {"0": "info", "1": "low", "2": "medium", "3": "high"}[risk],
                                 "confidence": text(str(alert.get("confidence", "unspecified")), 50),
                                 "target": target, "evidence": text(alert.get("desc", "No description supplied")),
                                 "remediation": text(alert.get("solution", "Review original ZAP guidance")),
                                 "instance_count": len(instances),
                                 "locations": [text(i["uri"], 2048) for i in instances]})
    elif kind == "trivy":
        if document.get("SchemaVersion") != 2:
            raise ValueError("Only Trivy schema 2 is supported")
        for result in items(document["Results"], 100):
            target = text(result["Target"], 2048)
            for field in ("Misconfigurations", "Secrets", "Licenses"):
                omitted += len(items(result.get(field) or []))
            for vuln in items(result.get("Vulnerabilities") or []):
                severity = text(vuln["Severity"], 20).lower()
                if severity not in ("unknown", "low", "medium", "high", "critical"):
                    raise ValueError("Invalid Trivy severity")
                identifier = text(vuln["VulnerabilityID"], 200)
                fixed = text(vuln.get("FixedVersion", ""), 200)
                findings.append({"title": text(vuln.get("Title") or identifier, 300), "rule_id": identifier,
                                 "severity": severity, "target": target,
                                 "package": text(vuln["PkgName"], 200),
                                 "installed_version": text(vuln["InstalledVersion"], 200), "fixed_version": fixed,
                                 "evidence": text(vuln.get("Description") or "Package advisory reported by Trivy"),
                                 "remediation": f"Review upstream fix {fixed} and compatibility before upgrading." if fixed else "No fixed version supplied; review upstream guidance."})
    else:
        raise ValueError("Unknown report format")
    if len(findings) > 1000:
        raise ValueError("Split reports into at most 1000 findings")
    unique = {}
    for finding in findings:
        fingerprint = hashlib.sha256(json.dumps(finding, sort_keys=True).encode()).hexdigest()
        unique[fingerprint] = {**finding, "id": fingerprint, "status": "imported; needs review"}
    return {"version": "1.0", "assessed_at": datetime.now(UTC).isoformat(),
            "verdict": "Imported tool observations; no fraud verdict or confirmed exploitation",
            "source": {"tool": kind, "version": version, "provenance": "operator-supplied; not authenticated"},
            "evidence_sha256": hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest(),
            "coverage": {"input_results": len(findings), "unique_findings": len(unique),
                         "duplicates_removed": len(findings)-len(unique), "omitted_non_vulnerability_records": omitted},
            "findings": list(unique.values()),
            "limitations": "Subset import only. Trivy imports package vulnerabilities, not secrets, licenses or misconfigurations. ZAP imports alert descriptions and URI locations, not HTTP requests, responses, attack payloads or instance evidence. Tool labels are unverified. Empty findings do not prove a successful or complete scan. Original report remains authoritative. Remove sensitive data before uploading."}
