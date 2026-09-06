"""SkyRecon application entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select

from app import audit, services
from app.config import get_settings
from app.db import get_engine, init_db
from app.models import User
from app.routers import admin, auth, intel
from app.security import passwords
from app.security.crypto import FieldContext, get_vault
from app.security.headers import SecurityHeadersMiddleware

log = logging.getLogger("skyrecon")
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

STATIC_DIR = Path(__file__).parent / "static"


def bootstrap(session: Session) -> None:
    """Create the first administrator and the built-in rule pack."""
    settings = get_settings()
    added = services.seed_builtin_rules(session)
    if added:
        log.info("seeded %d built-in detection rules", added)

    if session.exec(select(User)).first() is not None:
        return

    password = settings.bootstrap_password
    generated = False
    if not password:
        import secrets

        password = secrets.token_urlsafe(18) + "Aa1!"
        generated = True

    vault = get_vault()
    user = User(
        email_index=vault.blind_index(settings.bootstrap_email, "user-email"),
        email_sealed="", password_hash=passwords.hash_password(password),
        role="admin",
    )
    user.email_sealed = vault.seal(
        settings.bootstrap_email, FieldContext("users", "email", user.id)
    )
    session.add(user)
    session.commit()
    audit.record(session, action="system.bootstrap", target=user.id,
                 detail={"email": settings.bootstrap_email})

    if generated:
        log.warning(
            "\n%s\n  FIRST-RUN ADMINISTRATOR CREATED\n  e-mail:   %s\n  password: %s\n"
            "  Change it immediately — this is printed once.\n%s",
            "=" * 66, settings.bootstrap_email, password, "=" * 66,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_db()
    with Session(get_engine()) as session:
        bootstrap(session)
    log.info("SkyRecon ready in %s mode", settings.env)
    yield


app = FastAPI(
    title="SkyRecon",
    version="2.0.0",
    description=(
        "Threat intelligence and detection platform. Indicators, telemetry and "
        "audit records are encrypted at rest with per-field AES-256-GCM."
    ),
    lifespan=lifespan,
    docs_url=None if get_settings().is_production else "/docs",
    redoc_url=None,
)

app.add_middleware(SecurityHeadersMiddleware, hsts=get_settings().is_production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

app.include_router(auth.router)
app.include_router(intel.router)
app.include_router(admin.router)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    """Never leak a stack trace to a client; log it instead."""
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "internal error"},
    )


@app.get("/api/health", tags=["system"])
def health():
    return {"status": "ok", "service": "skyrecon", "version": app.version}


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC_DIR / "index.html")
