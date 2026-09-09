"""
Live, passive threat-intel lookups — WHOIS/RDAP and certificate transparency.

Unlike app/ioc/enrich.py and app/geoip.py, every function here makes an
outbound HTTP request to a public registry or log (rdap.org, crt.sh). It is
still strictly passive: nothing here connects to the indicator's own
infrastructure — no TLS handshake against the target, no port scan, no
active probing. It only reads records that registries and certificate
authorities already published for anyone to query.

Called on demand from a single endpoint (GET /api/indicators/{id}/deep-
enrich), never from the hot ingest/scoring path in app/services.py, so a
slow or unreachable public service never affects bulk ingest.
"""

from __future__ import annotations

import re

import httpx2

_TIMEOUT = 6.0
_HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def _get_json(url: str):
    try:
        resp = httpx2.get(url, timeout=_TIMEOUT, follow_redirects=True,
                           headers={"Accept": "application/json", "User-Agent": "skyrecon-intel/1.0"})
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def _vcard_fn(entity: dict) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            return item[3]
    return None


def rdap_domain(domain: str) -> dict:
    """Registrar, key dates and nameservers for a domain, or {} if unavailable."""
    data = _get_json(f"https://rdap.org/domain/{domain}")
    if not isinstance(data, dict):
        return {}

    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) or []}
    registrar = None
    for ent in data.get("entities", []) or []:
        if "registrar" in (ent.get("roles") or []):
            registrar = _vcard_fn(ent)
            break
    nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) or [] if ns.get("ldhName")]

    out = {
        "registrar": registrar,
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "status": data.get("status") or [],
        "nameservers": nameservers,
    }
    return {k: v for k, v in out.items() if v}


def rdap_ip(ip: str) -> dict:
    """Network name, org and ASN for an IP, or {} if unavailable."""
    data = _get_json(f"https://rdap.org/ip/{ip}")
    if not isinstance(data, dict):
        return {}

    org = None
    for ent in data.get("entities", []) or []:
        org = _vcard_fn(ent)
        if org:
            break
    asns = data.get("arin_originas0_originautnums") or []
    start, end = data.get("startAddress"), data.get("endAddress")

    out = {
        "network_name": data.get("name"),
        "network_org": org,
        "network_range": f"{start}–{end}" if start and end else None,
        "country": data.get("country"),
        "asn": asns[0] if asns else None,
    }
    return {k: v for k, v in out.items() if v}


def _base_domain(host: str) -> str:
    """Last two labels — a heuristic, not public-suffix-list-aware."""
    parts = host.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def cert_transparency(domain: str) -> dict:
    """
    Certificate history from public CT logs (crt.sh): issuers, validity span,
    and any *other* base domain seen sharing a certificate with this one —
    a strong signal when it shows up (shared/bulletproof hosting, phishing
    kits reusing infrastructure), unremarkable when it's just subdomains of
    the same site.
    """
    data = _get_json(f"https://crt.sh/?q={domain}&output=json")
    if not isinstance(data, list) or not data:
        return {}

    base = _base_domain(domain)
    issuers, hosts, not_before, not_after = set(), set(), [], []
    for row in data[:500]:
        if row.get("issuer_name"):
            issuers.add(row["issuer_name"])
        if row.get("not_before"):
            not_before.append(row["not_before"])
        if row.get("not_after"):
            not_after.append(row["not_after"])
        for field in ("common_name", "name_value"):
            for name in (row.get(field) or "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and _HOSTNAME_RE.match(name):
                    hosts.add(name)

    related = sorted({_base_domain(h) for h in hosts} - {base})

    out = {
        "cert_issuers": sorted(issuers),
        "cert_first_seen": min(not_before) if not_before else None,
        "cert_last_seen": max(not_after) if not_after else None,
        "cert_count": len(data),
        "related_domains": related[:25],
    }
    return {k: v for k, v in out.items() if v not in (None, [], "")}
