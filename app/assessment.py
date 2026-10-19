"""Bounded, non-exploit assessment. Observations are not proof of fraud."""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit


def target_url(value: str) -> tuple[str, str]:
    if len(value) > 2048 or any(ord(c) < 33 for c in value):
        raise ValueError("URL contains whitespace/control characters or is too long")
    p = urlsplit(value)
    if p.scheme != "https" or not p.hostname or p.username or p.password:
        raise ValueError("Use an HTTPS URL without credentials")
    if p.port not in (None, 443) or p.fragment or p.query:
        raise ValueError("Only port 443; query strings and fragments are excluded")
    host = p.hostname.encode("idna").decode("ascii").lower()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
        raise ValueError("Invalid hostname")
    return host, p.path or "/"


def collect(url: str) -> dict:
    """One TLS-verified GET, pinned DNS, no redirects/cookies/proxies/JS."""
    host, path = target_url(url)
    allowed = {s.strip().lower() for s in os.getenv("SKYRECON_SCAN_HOSTS", "").split(",") if s.strip()}
    if host not in allowed:
        raise ValueError("Target is not in the operator-approved exact-host allowlist")
    answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    addresses = sorted({a[4][0] for a in answers})
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError("Private, reserved and mixed public/private DNS targets are blocked")
    # Connect to the validated numeric address, but verify TLS against the hostname.
    raw = socket.create_connection((addresses[0], 443), timeout=5)
    conn = http.client.HTTPConnection(host, timeout=5)
    try:
        conn.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        conn.request("GET", path, headers={"Host": host, "User-Agent": "SkyRecon-Assessment/1.0", "Accept-Encoding": "identity"})
        response = conn.getresponse()
        headers = response.getheaders()
        # No response body is retained or interpreted; cookie values are discarded.
        return {"url": url, "status": response.status,
                "headers": {k.lower(): v for k, v in headers if k.lower() != "set-cookie"},
                "cookie_attributes": [";".join(v.split(";")[1:]) for k, v in headers if k.lower() == "set-cookie"],
                "collected_at": datetime.now(UTC).isoformat(), "source": "single HTTPS GET; response headers only"}
    finally:
        conn.close()
        raw.close()


def assess(evidence: dict) -> dict:
    host, _ = target_url(evidence["url"])
    headers = {k.lower(): str(v) for k, v in evidence.get("headers", {}).items()}
    findings = []

    def add(code, severity, title, observed, remediation):
        findings.append({"id": code, "severity": severity, "title": title, "evidence": observed,
                             "remediation": remediation, "status": "needs review", "confidence": "observed configuration"})

    checks = [
        ("hsts", "strict-transport-security", "Enable HSTS after validating HTTPS across the service."),
        ("csp", "content-security-policy", "Define and test an application-specific Content Security Policy."),
        ("nosniff", "x-content-type-options", "Set X-Content-Type-Options: nosniff."),
        ("referrer", "referrer-policy", "Set an explicit restrictive Referrer-Policy."),
        ("permissions", "permissions-policy", "Restrict unused browser capabilities with Permissions-Policy."),
    ]
    for code, name, fix in checks:
        if name not in headers:
            add(code, "low", f"Missing {name}", "Not present in supplied response headers", fix)
    if "x-content-type-options" in headers and headers["x-content-type-options"].lower().strip() != "nosniff":
        add("nosniff-value", "low", "Invalid nosniff policy", "Header value is not nosniff", "Set nosniff.")
    csp = headers.get("content-security-policy", "")
    directives = {part.strip().split()[0].lower(): part.strip().split()[1:] for part in csp.split(";") if part.strip()}
    if "frame-ancestors" not in directives and headers.get("x-frame-options", "").lower() not in ("deny", "sameorigin"):
        add("framing", "medium", "No observed framing restriction", "Neither CSP frame-ancestors nor valid X-Frame-Options", "Restrict framing to trusted origins.")
    if any(x in directives.get("script-src", directives.get("default-src", [])) for x in ("'unsafe-eval'", "*")):
        add("csp-script", "medium", "Broad script policy", "Wildcard or unsafe-eval in script policy", "Use explicit trusted sources and remove unsafe-eval where possible.")
    hsts = headers.get("strict-transport-security", "")
    if hsts and not re.search(r"(?:^|;)\s*max-age\s*=\s*[1-9][0-9]*\s*(?:;|$)", hsts, re.I):
        add("hsts-age", "low", "HSTS not enabled with a positive duration", "No positive max-age directive", "Set an appropriate positive max-age after rollout testing.")
    if "server" in headers or "x-powered-by" in headers:
        add("banner", "info", "Technology banner exposed", "Server or X-Powered-By header present", "Minimize unnecessary version disclosure; confirm applicability before CVE matching.")
    if headers.get("access-control-allow-origin") == "*":
        add("cors", "info", "Public cross-origin access", "Access-Control-Allow-Origin is wildcard", "Confirm this response is intended to be public. This alone is not a vulnerability.")
    for index, attrs in enumerate(evidence.get("cookie_attributes", [])):
        flags = {x.strip().split("=", 1)[0].lower() for x in attrs.split(";")}
        missing = sorted({"secure", "httponly", "samesite"} - flags)
        if missing:
            add(f"cookie-{index}", "low", "Cookie attributes require review", f"Cookie #{index+1}: missing {', '.join(missing)}", "Apply flags appropriate to the cookie purpose; HttpOnly is not appropriate for every cookie.")
    if host.startswith("xn--") or ".xn--" in host:
        add("idn", "info", "Internationalized domain", host, "Check the intended brand spelling. IDN use does not imply fraud.")
    status = evidence.get("status", 200)
    incomplete = status < 200 or status >= 300
    return {"version": "1.0", "target": host, "assessed_at": datetime.now(UTC).isoformat(),
            "source": evidence.get("source", "operator-supplied evidence; not independently verified"),
            "evidence_sha256": hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest(),
            "coverage": {"implemented_check_families": 12, "scope": "one response; headers, cookie flags and hostname", "incomplete_response": incomplete},
            "verdict": "Insufficient evidence to determine fraud",
            "findings": findings, "not_tested": ["SQL injection", "XSS exploitation", "authorization bypass", "business logic", "malware execution", "all CVEs", "identity of site owner"],
            "limitations": "Configuration observations only. A missing header is not proof of exploitation. Redirects and blocked/error pages do not assess the destination application."}


def phone_lookup(value: str) -> dict:
    normalized = re.sub(r"[ ()-]", "", value)
    if not re.fullmatch(r"\+[1-9][0-9]{6,14}", normalized):
        raise ValueError("Use international +country-code format (7-15 digits)")
    region = next((v for k, v in [("+91", "India"), ("+44", "United Kingdom numbering plan"), ("+1", "North American Numbering Plan (shared)")] if normalized.startswith(k)), "Not resolved")
    result = {"number": normalized, "format": "E.164-shaped; assignment/active status unverified", "numbering_region": region,
              "owner": "Owner unknown", "location": "Current location unavailable", "source": None,
              "limitations": "Numbering region is not device location; caller ID can be spoofed. No private identity directory is queried."}
    directory = os.getenv("SKYRECON_BUSINESS_DIRECTORY")
    if directory:
        path = Path(directory)
        if path.stat().st_size > 1_000_000:
            raise ValueError("Business directory exceeds size limit")
        data = json.loads(path.read_text(encoding="utf-8"))
        record = data.get(normalized)
        if record and record.get("kind") == "public_business" and record.get("name") and record.get("source_url", "").startswith("https://"):
            verified = datetime.fromisoformat(record.get("verified_at", ""))
            if verified.tzinfo is None:
                raise ValueError("Directory verification time must include timezone")
            age = (datetime.now(UTC) - verified).total_seconds()
            if 0 <= age <= 90 * 86400:
                result.update(owner=record["name"], source=record["source_url"], verified_at=record["verified_at"],
                              attribution="Operator-verified public business listing; not subscriber identity verification")
    return result
