"""STIX 2.1 and MISP export, so indicators leave in a format tools accept."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.models import IOCType

_PATTERN = {
    IOCType.IPV4: "[ipv4-addr:value = '{v}']",
    IOCType.IPV6: "[ipv6-addr:value = '{v}']",
    IOCType.DOMAIN: "[domain-name:value = '{v}']",
    IOCType.URL: "[url:value = '{v}']",
    IOCType.EMAIL: "[email-addr:value = '{v}']",
    IOCType.MD5: "[file:hashes.'MD5' = '{v}']",
    IOCType.SHA1: "[file:hashes.'SHA-1' = '{v}']",
    IOCType.SHA256: "[file:hashes.'SHA-256' = '{v}']",
    IOCType.CVE: "[vulnerability:name = '{v}']",
}

_MISP_TYPE = {
    IOCType.IPV4: "ip-dst", IOCType.IPV6: "ip-dst", IOCType.DOMAIN: "domain",
    IOCType.URL: "url", IOCType.EMAIL: "email-src", IOCType.MD5: "md5",
    IOCType.SHA1: "sha1", IOCType.SHA256: "sha256", IOCType.CVE: "vulnerability",
}

_TLP_TO_MARKING = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red":   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def pattern_for(value: str, ioc_type: str) -> str:
    try:
        template = _PATTERN[IOCType(ioc_type)]
    except (ValueError, KeyError):
        template = "[x-unknown:value = '{v}']"
    return template.format(v=value.replace("'", "\\'"))


def indicator_object(record: dict) -> dict:
    """One STIX 2.1 `indicator` SDO from a decrypted indicator row."""
    created = record.get("first_seen") or datetime.now(UTC)
    modified = record.get("last_seen") or created
    labels = [t for t in (record.get("tags") or "").split(",") if t]
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, record['value'])}",
        "created": _iso(created),
        "modified": _iso(modified),
        "name": f"{record['ioc_type']}: {record['value']}",
        "pattern": pattern_for(record["value"], record["ioc_type"]),
        "pattern_type": "stix",
        "valid_from": _iso(created),
        "confidence": int(record.get("confidence", 50)),
        "labels": labels or ["malicious-activity"],
    }
    marking = _TLP_TO_MARKING.get(str(record.get("tlp", "amber")).lower())
    if marking:
        obj["object_marking_refs"] = [marking]
    if record.get("notes"):
        obj["description"] = record["notes"]
    return obj


def bundle(records: list[dict]) -> dict:
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [indicator_object(r) for r in records],
    }


def misp_event(records: list[dict], *, info: str = "SkyRecon export") -> dict:
    now = datetime.now(UTC)
    attributes = []
    for r in records:
        try:
            mtype = _MISP_TYPE[IOCType(r["ioc_type"])]
        except (ValueError, KeyError):
            continue
        attributes.append({
            "type": mtype,
            "category": "Network activity",
            "value": r["value"],
            "to_ids": int(r.get("confidence", 50)) >= 60,
            "comment": r.get("notes") or "",
            "timestamp": str(int(now.timestamp())),
        })
    return {"Event": {
        "info": info,
        "date": now.strftime("%Y-%m-%d"),
        "threat_level_id": "2",
        "analysis": "2",
        "distribution": "0",
        "Attribute": attributes,
    }}
