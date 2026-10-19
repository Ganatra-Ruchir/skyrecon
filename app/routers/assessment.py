"""Authenticated assessment endpoints; no public scan proxy."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlmodel import Session

from app import assessment, audit, sarif_import
from app.db import get_session
from app.deps import rate_limited, requires
from app.models import User
from app.security.rbac import Permission

router = APIRouter(prefix="/api/assessment", tags=["assessment"], dependencies=[Depends(rate_limited)])


@router.get("/catalogue")
def catalogue(q: str = Query(min_length=4, max_length=100),
              _: User = Depends(requires(Permission.IOC_READ))):
    path = os.getenv("SKYRECON_CVE_CATALOGUE")
    if not path or not Path(path).is_file():
        return {"state": "not configured", "records": [], "confirmed_target_findings": 0}
    try:
        with sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True) as db:
            term = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            rows = db.execute("SELECT id, published, modified, description FROM cves WHERE id LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' LIMIT 50", (f"%{term}%", f"%{term}%")).fetchall()
            count = db.execute("SELECT count(*) FROM cves").fetchone()[0]
        return {"state": "reference only", "catalogue_count": count,
                "records": [dict(zip(["id", "published", "modified", "description"], row, strict=True)) for row in rows],
                "limit": 50, "confirmed_target_findings": 0,
                "limitations": "Keyword search is not product/version applicability or a vulnerability test."}
    except sqlite3.Error as exc:
        raise HTTPException(503, "Catalogue unavailable") from exc


class Evidence(BaseModel):
    url: str = Field(max_length=2048)
    status: int = Field(default=200, ge=100, le=599)
    headers: dict[Annotated[str, Field(max_length=128)], Annotated[str, Field(max_length=4096)]] = Field(default_factory=dict, max_length=64)
    cookie_attributes: list[Annotated[str, Field(max_length=1024)]] = Field(default_factory=list, max_length=50)


class Scan(BaseModel):
    url: str = Field(max_length=2048)
    authorization_reference: str = Field(min_length=8, max_length=200)


class Phone(BaseModel):
    number: str = Field(max_length=32)


class ToolReport(BaseModel):
    report_json: str = Field(min_length=2, max_length=524288)


@router.post("/sarif")
def import_report(body: ToolReport, session: Session = Depends(get_session), user: User = Depends(requires(Permission.IOC_WRITE))):
    try:
        result = sarif_import.normalize(json.loads(body.report_json))
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise HTTPException(422, "Invalid or unsupported SARIF subset; use 2.1.0 inline runs and plain message.text, maximum 1000 results") from exc
    audit.record(session, action="assessment.sarif", actor_id=user.id,
                 detail={"digest": result["evidence_sha256"], "coverage": result["coverage"]})
    return result


@router.post("/evidence")
def review(body: Evidence, session: Session = Depends(get_session), user: User = Depends(requires(Permission.IOC_WRITE))):
    try:
        result = assessment.assess(body.model_dump())
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit.record(session, action="assessment.evidence", actor_id=user.id, detail={"report": result})
    return result


@router.post("/scan")
def scan(body: Scan, session: Session = Depends(get_session), user: User = Depends(requires(Permission.USER_MANAGE))):
    # Only administrators may trigger even the bounded network request.
    try:
        assessment.target_url(body.url)
        audit.record(session, action="assessment.scan.request", actor_id=user.id,
                     detail={"url": body.url, "authorization_reference": body.authorization_reference})
        result = assessment.assess(assessment.collect(body.url))
    except (ValueError, OSError, assessment.http.client.HTTPException) as exc:
        audit.record(session, action="assessment.scan.failed", actor_id=user.id, outcome="failed")
        raise HTTPException(422, "Scan unavailable: verify authorized host, public DNS and TLS connectivity") from exc
    audit.record(session, action="assessment.scan.complete", actor_id=user.id, detail={"report": result})
    return result


@router.post("/phone")
def phone(body: Phone, session: Session = Depends(get_session), user: User = Depends(requires(Permission.IOC_WRITE))):
    try:
        result = assessment.phone_lookup(body.number)
    except (ValueError, OSError, TypeError, AttributeError) as exc:
        raise HTTPException(422, "Invalid number or unavailable business directory") from exc
    audit.record(session, action="assessment.phone", actor_id=user.id, detail={"number": result["number"]})
    return result
