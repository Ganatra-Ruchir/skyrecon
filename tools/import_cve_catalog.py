"""Import operator-downloaded NVD 2.0 JSON into a searchable local catalogue.

Catalogue entries are reference intelligence, never confirmed target findings.
Usage: python tools/import_cve_catalog.py feed.json catalogue.sqlite
"""
import argparse
import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path


def import_feed(source: Path, destination: Path) -> int:
    if source.stat().st_size > 100_000_000:
        raise ValueError("Use NVD API pages or split feeds below 100 MB")
    document = json.loads(source.read_text(encoding="utf-8"))
    rows = []
    for item in document["vulnerabilities"]:
        cve = item["cve"]
        identifier = cve["id"]
        if not re.fullmatch(r"CVE-(2024|2025|2026)-[0-9]{4,}", identifier):
            continue
        if cve.get("vulnStatus") == "Rejected":
            continue
        description = next((x["value"] for x in cve.get("descriptions", []) if x["lang"] == "en"), "No English description")
        rows.append((identifier, cve.get("published", ""), cve.get("lastModified", ""), description,
                     json.dumps(cve.get("configurations", [])), json.dumps(cve.get("metrics", {})),
                     datetime.now(UTC).isoformat()))
    with sqlite3.connect(destination) as db:
        db.execute("CREATE TABLE IF NOT EXISTS cves (id TEXT PRIMARY KEY, published TEXT, modified TEXT, description TEXT, applicability TEXT, metrics TEXT, imported_at TEXT)")
        db.executemany("INSERT OR REPLACE INTO cves VALUES (?,?,?,?,?,?,?)", rows)
    return len(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(f"Imported {import_feed(args.source, args.destination)} reference records; zero target vulnerabilities confirmed.")
