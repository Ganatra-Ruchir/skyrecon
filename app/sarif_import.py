"""Normalize a bounded SARIF 2.1.0 subset without running tools or following URIs."""
import hashlib
import json
from datetime import UTC, datetime


def normalize(document: dict) -> dict:
    if document.get("version") != "2.1.0":
        raise ValueError("Only SARIF 2.1.0 is supported")
    runs = document.get("runs")
    if not isinstance(runs, list) or not 1 <= len(runs) <= 20:
        raise ValueError("Supply 1-20 inline runs")
    findings, sources, seen = [], [], set()
    count = 0
    for run in runs:
        if run.get("externalPropertyFileReferences"):
            raise ValueError("External properties are unsupported; supply an inline report")
        driver = run["tool"]["driver"]
        name = driver["name"]
        if not isinstance(name, str) or not name.strip() or len(name) > 200:
            raise ValueError("Invalid tool name")
        sources.append({"name": name, "version": str(driver.get("version", "unspecified"))[:100], "provenance": "operator-supplied; not authenticated"})
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError("Results must be an array")
        count += len(results)
        if count > 1000:
            raise ValueError("Split reports into at most 1000 results")
        for result in results:
            message = result["message"].get("text")
            if not isinstance(message, str) or not message.strip() or len(message) > 4096:
                raise ValueError("Each result needs plain message.text, at most 4096 characters")
            rule = str(result.get("ruleId", "unspecified"))[:200]
            level = result.get("level", "warning")
            if level not in ("none", "note", "warning", "error"):
                raise ValueError("Invalid SARIF level")
            locations = []
            for loc in result.get("locations", [])[:10]:
                physical = loc.get("physicalLocation", {})
                locations.append({"uri": str(physical.get("artifactLocation", {}).get("uri", "unspecified"))[:2048],
                                  "line": physical.get("region", {}).get("startLine")})
            signature = json.dumps([name, rule, message, locations], sort_keys=True)
            fingerprint = hashlib.sha256(signature.encode()).hexdigest()
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            findings.append({"id": fingerprint, "title": f"{name}: {rule}", "severity": f"tool level: {level}",
                             "status": "imported; needs review", "evidence": message, "locations": locations,
                             "suppressed_in_source": bool(result.get("suppressions")),
                             "remediation": "Review the original tool report, rule guidance and target applicability. No exploit validation performed."})
    return {"version": "1.0", "assessed_at": datetime.now(UTC).isoformat(),
            "verdict": "Imported tool observations; no fraud verdict or confirmed exploitation",
            "source": sources, "evidence_sha256": hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest(),
            "coverage": {"input_results": count, "unique_findings": len(findings), "duplicates_removed": count-len(findings)},
            "findings": findings, "limitations": "SARIF subset import only, not full schema validation. Levels are tool levels, not CVSS. No external links, code, artifacts or fixes executed. Suppression presence is retained, not adjudicated. Empty results do not establish a successful scan. Original report remains authoritative."}
