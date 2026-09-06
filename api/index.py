"""
Vercel serverless entrypoint.

Vercel runs Python as a function, not as a long-lived server, and two
consequences shape everything below.

*The filesystem is read-only apart from `/tmp`, and `/tmp` is wiped when the
function goes cold.* A SQLite database there survives minutes, not days, so
accounts, indicators, alerts and the audit chain all reset on their own. A
tamper-evident audit log that resets itself is not tamper-evident, which is why
this file treats a Vercel instance as a **demo** rather than a deployment.

*Every cold start is a new process.* The rate limiter and the anomaly model
start empty each time, so both are weaker here than in a container that stays
up.

For an instance that keeps its data and its detection state, deploy the
Dockerfile to Render or Fly — `render.yaml` and `fly.toml` are in the
repository root, and `DEPLOYING.md` walks through both.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

log = logging.getLogger("skyrecon.vercel")

# Ephemeral by construction: the only writable path is /tmp, and it is wiped.
os.environ.setdefault("SKYRECON_DATABASE_URL", "sqlite:////tmp/skyrecon.db")

# ── production, or an honest demo ────────────────────────────────────────
#
# `app.config` refuses to start in production without a real master key and JWT
# secret, and it is right to. But a repository's `.env.example` lists those keys
# with blank values, and Vercel offers to import that file when a project is
# created — which produces exactly the configuration the check exists to
# reject, and a 500 with no explanation.
#
# So the decision is made here, explicitly: production mode is honoured when the
# secrets that make it meaningful are actually present, and otherwise the
# instance runs as the demo it really is. It never silently runs "production"
# without production's protections.
_HAS_SECRETS = bool(os.environ.get("SKYRECON_MASTER_KEY")) and bool(
    os.environ.get("SKYRECON_JWT_SECRET")
)

if not _HAS_SECRETS:
    log.warning(
        "SKYRECON_MASTER_KEY and SKYRECON_JWT_SECRET are not set, so this "
        "instance is running in demo mode: keys are generated per cold start "
        "and every restart discards the database. Set both in the Vercel "
        "project settings for a real deployment."
    )
    os.environ["SKYRECON_ENV"] = "development"
    # A demo nobody can sign in to is not a demo. This password protects a
    # throwaway instance holding only synthetic data that deletes itself every
    # few minutes; it is not a secret, and it is deliberately not a master key.
    os.environ.setdefault("SKYRECON_BOOTSTRAP_PASSWORD", "SkyRecon-Demo-2026!")
    os.environ.setdefault("SKYRECON_REQUIRE_ADMIN_MFA", "false")

from app.main import app  # noqa: E402  (the environment must be settled first)


# ── give the demo something to show ────────────────────────────────────
def _seed_demo() -> None:
    """
    Populate a fresh cold start with the synthetic incident from `seed.py`.

    Without this the dashboard opens empty, because `/tmp` was wiped. It is
    skipped entirely on a configured instance: real deployments get their data
    from real traffic, not from a fixture.
    """
    from sqlmodel import Session, select

    from app import services
    from app.db import get_engine
    from app.models import Indicator

    report = """
    INCIDENT 2026-0917 - commodity loader campaign

    Initial access via spearphishing link hxxps://secure-login-verify[.]tk/account/update.exe
    Second stage pulled from hxxp://45.155.205.233/gate.php
    C2 rendezvous over algorithmically generated domains: kqjxvbwzrtplmn[.]top and
    xzmqvbnrtkplwd[.]xyz. Operator mailbox: payments[at]invoice-desk[dot]ru
    Payload hashes: 44d88612fea8a8f36de82e1278abb02f (loader),
    9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 (stage2)
    Exploited CVE-2024-3400 on the perimeter appliance.
    Internal hosts 10.4.2.19 and 192.168.30.7 were affected - do not block these.
    Legitimate traffic to github.com and microsoft.com also observed.
    """

    events = [
        {"source": "proxy", "kind": "http",
         "payload": "GET http://45.155.205.233/gate.php HTTP/1.1 UA=curl/8.4",
         "src_ip": "10.4.2.19", "dst_ip": "45.155.205.233",
         "bytes_out": 812, "bytes_in": 40311, "duration_ms": 240},
        {"source": "edr", "kind": "process",
         "payload": "powershell.exe -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA==",
         "src_ip": "10.4.2.19", "bytes_out": 0, "bytes_in": 0, "duration_ms": 90},
        {"source": "dns", "kind": "dns", "payload": "query kqjxvbwzrtplmn.top A",
         "src_ip": "10.4.2.19", "bytes_out": 74, "bytes_in": 132, "duration_ms": 12},
        {"source": "netflow", "kind": "netflow",
         "payload": "bulk transfer to 45.155.205.233",
         "src_ip": "10.4.2.19", "dst_ip": "45.155.205.233",
         "bytes_out": 41_500_000, "bytes_in": 9_400, "duration_ms": 88_000},
    ]

    with Session(get_engine()) as session:
        if session.exec(select(Indicator)).first() is not None:
            return  # already seeded this cold start
        services.bulk_ingest(
            session, text=report, source="report", severity="high",
            tags=["campaign-0917", "loader"],
        )
        for event in events:
            services.ingest_event(session, **event)
    log.info("demo data seeded")


if not _HAS_SECRETS:
    # `@app.on_event("startup")` is silently ignored once an app defines a
    # `lifespan` context, which `app.main` does — the handler registers and
    # never runs. Composing the lifespan is the version that actually fires,
    # and it fires after `init_db()`, which the seeding needs.
    _original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def _lifespan_with_demo_data(scope):
        async with _original_lifespan(scope):
            try:
                _seed_demo()
            except Exception:  # noqa: BLE001 - a fixture must never break boot
                log.exception("demo seeding failed; the instance is still usable")
            yield

    app.router.lifespan_context = _lifespan_with_demo_data


__all__ = ["app"]
