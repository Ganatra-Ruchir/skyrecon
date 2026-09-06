"""Populate a running instance with a realistic scenario (synthetic data).

Everything below is fabricated for demonstration: the indicators are drawn from
public documentation samples and RFC-reserved space, and no real host is
contacted.  Usage:  python seed.py [base-url]
"""

import json
import os
import random
import sys

import httpx2

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8099"
_client = httpx2.Client(base_url=BASE, timeout=30.0)


def call(path, body=None, token=None, method=None):
    verb = method or ("POST" if body is not None else "GET")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = _client.request(verb, path, json=body, headers=headers)
    r.raise_for_status()
    return r.json() if r.content else None


# Demo credentials for a throwaway local instance. Override with the env vars
# when seeding anything you did not create thirty seconds ago.
EMAIL = os.environ.get("SKYRECON_BOOTSTRAP_EMAIL", "admin@skyrecon.local")
PASSWORD = os.environ.get("SKYRECON_BOOTSTRAP_PASSWORD", "Bootstrap-Admin-2026!")  # nosec B105 - local demo default

tok = call("/api/auth/login", {"email": EMAIL, "password": PASSWORD})["access_token"]

report = """
INCIDENT 2026-0917 — commodity loader campaign

Initial access via spearphishing link hxxps://secure-login-verify[.]tk/account/update.exe
Second stage pulled from hxxp://45.155.205.233/gate.php
C2 rendezvous over algorithmically generated domains: kqjxvbwzrtplmn[.]top and
xzmqvbnrtkplwd[.]xyz. Operator mailbox: payments[at]invoice-desk[dot]ru
Payload hashes: 44d88612fea8a8f36de82e1278abb02f (loader),
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 (stage2)
Exploited CVE-2024-3400 on the perimeter appliance.
Internal hosts 10.4.2.19 and 192.168.30.7 were affected — do not block these.
Legitimate traffic to github.com and microsoft.com also observed.
"""
ingest = call("/api/indicators/bulk",
              {"text": report, "source": "report", "severity": "high",
               "tags": ["campaign-0917", "loader"]}, tok)
print(f"bulk ingest → extracted={ingest['extracted']} stored={len(ingest['created'])} "
      f"discarded={len(ingest['rejected'])}")
for v in ingest["created"]:
    print("   stored:", v)

# ── 1. two weeks of unremarkable traffic, so the detector has a baseline ──
# A SOC never starts from zero: the anomaly model is only meaningful against
# what "normal" actually looked like here.
rng = random.Random(20260917)  # nosec B311 - synthetic demo traffic, not security


def jitter(base: int) -> int:
    """±40% wobble so the baseline has real variance to measure against."""
    return max(0, int(base * rng.uniform(0.65, 1.45)))


MIX = [
    ("proxy", "http", "GET https://intranet.corp/app/{i} HTTP/1.1", 900, 6000, 140),
    ("proxy", "http", "POST https://crm.corp/api/tickets/{i} HTTP/1.1", 2400, 1800, 260),
    ("dns", "dns", "query updates.corp A", 70, 120, 14),
    ("netflow", "netflow", "session to 10.4.9.{i} :443", 18_000, 240_000, 3_400),
]
for i in range(45):
    src, kind, tmpl, out, inn, dur = MIX[i % len(MIX)]
    call("/api/events", {"source": src, "kind": kind,
                         "payload": tmpl.format(i=i % 24),
                         "bytes_out": jitter(out), "bytes_in": jitter(inn),
                         "duration_ms": jitter(dur)}, tok)
print("baseline: 45 routine events across proxy, dns and netflow")

# ── 2. the incident ────────────────────────────────────────────────────────
events = [
    ("initial callback, known C2",
     {"source": "proxy", "kind": "http",
      "payload": "GET http://45.155.205.233/gate.php HTTP/1.1 UA=curl/8.4",
      "src_ip": "10.4.2.19", "dst_ip": "45.155.205.233",
      "bytes_out": 812, "bytes_in": 40311, "duration_ms": 240}),
    ("encoded PowerShell on the host",
     {"source": "edr", "kind": "process",
      "payload": "powershell.exe -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA==",
      "src_ip": "10.4.2.19", "bytes_out": 0, "bytes_in": 0, "duration_ms": 90}),
    ("DGA rendezvous",
     {"source": "dns", "kind": "dns", "payload": "query kqjxvbwzrtplmn.top A",
      "src_ip": "10.4.2.19", "bytes_out": 74, "bytes_in": 132, "duration_ms": 12}),
    ("41 MB outbound — nothing in the rule pack describes this",
     {"source": "netflow", "kind": "netflow", "payload": "bulk transfer to 45.155.205.233",
      "src_ip": "10.4.2.19", "dst_ip": "45.155.205.233",
      "bytes_out": 41_500_000, "bytes_in": 9_400, "duration_ms": 88_000}),
]
for label, e in events:
    r = call("/api/events", e, tok)
    line = (f"  risk={r['risk_score']:<6} matched={len(r['matched_indicators'])} "
            f"alerts={len(r['alerts_created'])} anomaly={r['anomaly']}")
    print(f"\n{label}\n{line}")
    for reason in r.get("anomaly_reasons") or []:
        print("    ·", reason)

s = call("/api/stats", token=tok)
print("\nstats:", json.dumps({k: s[k] for k in
      ("indicators", "alerts_open", "alerts_total", "events_24h", "rules_enabled")}))
print("severity:", json.dumps(s["by_severity"]))
print("attack coverage:", json.dumps({k: v for k, v in s["mitre_coverage"].items() if v}))
audit = call("/api/admin/audit?limit=5", token=tok)
print("audit chain intact:", audit["chain_intact"], "| entries:", len(audit["entries"]))
