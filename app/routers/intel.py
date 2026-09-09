"""Indicators, events, alerts, rules and exports."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlmodel import Session, col, func, select

from app import audit, services
from app.db import get_session
from app.deps import current_user, rate_limited, requires
from app.detect import mitre
from app.detect import rules as rule_engine
from app.ioc import stix
from app.models import Alert, AlertState, DetectionRule, Event, Indicator, User, utcnow
from app.schemas import (
    AlertOut,
    BulkIngestRequest,
    EventIn,
    EventOut,
    IndicatorIn,
    IndicatorOut,
    RuleIn,
    RuleOut,
    TriageRequest,
)
from app.security.crypto import FieldContext, get_vault
from app.security.rbac import Permission

router = APIRouter(prefix="/api", tags=["intel"], dependencies=[Depends(rate_limited)])


# ── indicators ──────────────────────────────────────────────────────────
@router.post("/indicators", response_model=IndicatorOut, status_code=status.HTTP_201_CREATED)
def create_indicator(body: IndicatorIn, session: Session = Depends(get_session),
                     user: User = Depends(requires(Permission.IOC_WRITE))):
    try:
        record, _ = services.upsert_indicator(
            session, value=body.value, ioc_type=body.ioc_type, source=body.source,
            severity=body.severity.value, confidence=body.confidence,
            tags=body.tags, tlp=body.tlp, notes=body.notes, actor_id=user.id,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return services.read_indicator(record)


@router.get("/search")
def search(q: str = Query(..., min_length=1, max_length=512),
           session: Session = Depends(get_session),
           _: User = Depends(requires(Permission.IOC_READ))):
    """
    Universal observable search: classify one pasted value (domain, IP,
    URL, hash, email, CVE — plus recognize-only formats like phone/UPI/IFSC/
    crypto/ASN) and say whether it's already stored. No new network calls;
    reuses the same type detection as ingest.
    """
    return services.universal_search(session, q)


@router.get("/indicators", response_model=list[IndicatorOut])
def list_indicators(
    session: Session = Depends(get_session),
    _: User = Depends(requires(Permission.IOC_READ)),
    ioc_type: str | None = None,
    severity: str | None = None,
    min_confidence: int = Query(0, ge=0, le=100),
    active_only: bool = True,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    stmt = select(Indicator)
    if ioc_type:
        stmt = stmt.where(Indicator.ioc_type == ioc_type)
    if severity:
        stmt = stmt.where(Indicator.severity == severity)
    if active_only:
        stmt = stmt.where(Indicator.is_active == True)  # noqa: E712
    stmt = stmt.order_by(col(Indicator.last_seen).desc()).offset(offset).limit(limit)

    out = [services.read_indicator(r) for r in session.exec(stmt).all()]
    return [r for r in out if r["effective_confidence"] >= min_confidence]


@router.get("/indicators/{indicator_id}", response_model=IndicatorOut)
def get_indicator(indicator_id: str, session: Session = Depends(get_session),
                  _: User = Depends(requires(Permission.IOC_READ))):
    record = session.get(Indicator, indicator_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "indicator not found")
    return services.read_indicator(record)


@router.post("/indicators/{indicator_id}/deep-enrich")
def deep_enrich(indicator_id: str, session: Session = Depends(get_session),
                user: User = Depends(requires(Permission.IOC_READ))):
    """
    Live, passive lookups (RDAP + certificate transparency) for one
    indicator. Unlike every other read in this router, this leaves the
    network — each call fetches a public registry or CT log, not the
    indicator's own infrastructure. Fetch on demand only; never wired into
    bulk ingest or list views.
    """
    record = session.get(Indicator, indicator_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "indicator not found")
    return services.deep_enrich_indicator(session, record, actor_id=user.id)


@router.delete("/indicators/{indicator_id}", status_code=status.HTTP_204_NO_CONTENT)
def retire_indicator(indicator_id: str, session: Session = Depends(get_session),
                     user: User = Depends(requires(Permission.IOC_DELETE))):
    record = session.get(Indicator, indicator_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "indicator not found")
    record.is_active = False
    session.add(record)
    session.commit()
    audit.record(session, action="ioc.retire", actor_id=user.id, target=indicator_id)


@router.post("/indicators/bulk")
def bulk(body: BulkIngestRequest, session: Session = Depends(get_session),
         user: User = Depends(requires(Permission.IOC_WRITE))):
    """Paste a threat report; keep what is genuinely an indicator."""
    return services.bulk_ingest(
        session, text=body.text, source=body.source,
        severity=body.severity.value, tags=body.tags, actor_id=user.id,
    )


@router.get("/indicators/export/{fmt}")
def export_indicators(fmt: str, session: Session = Depends(get_session),
                      user: User = Depends(requires(Permission.IOC_READ)),
                      min_confidence: int = Query(50, ge=0, le=100)):
    if fmt not in {"stix", "misp", "csv"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "format must be stix, misp or csv")

    records = [
        services.read_indicator(r, with_enrichment=False)
        for r in session.exec(
            select(Indicator).where(Indicator.is_active == True)  # noqa: E712
        ).all()
    ]
    records = [r for r in records if r["effective_confidence"] >= min_confidence]
    for r in records:
        r["confidence"] = r["effective_confidence"]
        r["tags"] = ",".join(r["tags"])

    audit.record(session, action="ioc.export", actor_id=user.id,
                 detail={"format": fmt, "count": len(records)})

    if fmt == "stix":
        return Response(json.dumps(stix.bundle(records), indent=2),
                        media_type="application/stix+json",
                        headers={"Content-Disposition": "attachment; filename=skyrecon-stix.json"})
    if fmt == "misp":
        return Response(json.dumps(stix.misp_event(records), indent=2),
                        media_type="application/json",
                        headers={"Content-Disposition": "attachment; filename=skyrecon-misp.json"})

    lines = ["value,type,severity,confidence,risk,source,tags,first_seen,last_seen"]
    for r in records:
        lines.append(",".join([
            f'"{r["value"]}"', r["ioc_type"], r["severity"], str(r["confidence"]),
            str(r["risk_score"]), r["source"], f'"{r["tags"]}"',
            r["first_seen"].isoformat(), r["last_seen"].isoformat(),
        ]))
    return Response("\n".join(lines), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=skyrecon-iocs.csv"})


# ── events ──────────────────────────────────────────────────────────────
@router.post("/events", response_model=EventOut, status_code=status.HTTP_201_CREATED)
def ingest(body: EventIn, session: Session = Depends(get_session),
           user: User = Depends(requires(Permission.EVENT_INGEST))):
    return services.ingest_event(
        session, source=body.source, kind=body.kind, payload=body.payload,
        src_ip=body.src_ip, dst_ip=body.dst_ip, bytes_out=body.bytes_out,
        bytes_in=body.bytes_in, duration_ms=body.duration_ms, actor_id=user.id,
    )


@router.get("/events")
def list_events(session: Session = Depends(get_session),
                _: User = Depends(requires(Permission.EVENT_READ)),
                limit: int = Query(50, ge=1, le=200)):
    vault = get_vault()
    rows = session.exec(
        select(Event).order_by(col(Event.received_at).desc()).limit(limit)
    ).all()
    def unseal(sealed: str | None, column: str, record_id: str) -> str | None:
        if not sealed:
            return None
        try:
            return vault.open(sealed, FieldContext("events", column, record_id))
        except Exception:
            return "<unreadable: key mismatch>"

    out = []
    for e in rows:
        payload = unseal(e.payload_sealed, "payload", e.id) or ""
        out.append({"id": e.id, "received_at": e.received_at, "source": e.source,
                    "kind": e.kind, "payload": payload[:2000],
                    "src_ip": unseal(e.src_ip_sealed, "src_ip", e.id),
                    "dst_ip": unseal(e.dst_ip_sealed, "dst_ip", e.id),
                    "bytes_out": e.bytes_out, "bytes_in": e.bytes_in,
                    "duration_ms": e.duration_ms,
                    "risk_score": e.risk_score})
    return out


# ── alerts ──────────────────────────────────────────────────────────────
@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(session: Session = Depends(get_session),
                _: User = Depends(requires(Permission.ALERT_READ)),
                state: str | None = None, severity: str | None = None,
                limit: int = Query(100, ge=1, le=500)):
    stmt = select(Alert)
    if state:
        stmt = stmt.where(Alert.state == state)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    stmt = stmt.order_by(col(Alert.score).desc(), col(Alert.created_at).desc()).limit(limit)
    return [services.read_alert(a) for a in session.exec(stmt).all()]


@router.post("/alerts/{alert_id}/triage", response_model=AlertOut)
def triage(alert_id: str, body: TriageRequest, session: Session = Depends(get_session),
           user: User = Depends(requires(Permission.ALERT_TRIAGE))):
    alert = session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    alert.state = body.state.value
    alert.assigned_to = user.id
    if body.state in {AlertState.RESOLVED, AlertState.FALSE_POSITIVE}:
        alert.resolved_at = utcnow()
    if body.note:
        alert.resolution_note_sealed = get_vault().seal(
            body.note, FieldContext("alerts", "resolution_note", alert.id)
        )
    session.add(alert)
    session.commit()
    session.refresh(alert)
    audit.record(session, action="alert.triage", actor_id=user.id, target=alert_id,
                 detail={"state": body.state.value})
    return services.read_alert(alert)


# ── rules ───────────────────────────────────────────────────────────────
@router.get("/rules", response_model=list[RuleOut])
def list_rules(session: Session = Depends(get_session),
               _: User = Depends(requires(Permission.RULE_READ))):
    return [
        {**r.model_dump(), "mitre": mitre.describe(r.mitre_techniques)}
        for r in session.exec(select(DetectionRule).order_by(DetectionRule.name)).all()
    ]


@router.post("/rules", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(body: RuleIn, session: Session = Depends(get_session),
                user: User = Depends(requires(Permission.RULE_WRITE))):
    ok, err = rule_engine.validate_expression(body.expression)
    if not ok:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"invalid rule: {err}")
    if session.exec(select(DetectionRule).where(DetectionRule.name == body.name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "a rule with that name exists")

    rule = DetectionRule(
        name=body.name, description=body.description, expression=body.expression,
        severity=body.severity.value, enabled=body.enabled,
        mitre_techniques=",".join(body.mitre_techniques),
    )
    session.add(rule)
    session.commit()
    session.refresh(rule)
    audit.record(session, action="rule.create", actor_id=user.id, target=rule.id,
                 detail={"name": rule.name})
    return {**rule.model_dump(), "mitre": mitre.describe(rule.mitre_techniques)}


@router.post("/rules/test")
def test_rule(expression: str, facts: dict, _: User = Depends(requires(Permission.RULE_READ))):
    """Dry-run a rule against sample facts before saving it."""
    ok, err = rule_engine.validate_expression(expression)
    if not ok:
        return {"valid": False, "error": err, "matched": None}
    try:
        return {"valid": True, "error": None,
                "matched": rule_engine.evaluate(expression, facts)}
    except rule_engine.RuleError as exc:
        return {"valid": False, "error": str(exc), "matched": None}


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(rule_id: str, session: Session = Depends(get_session),
                user: User = Depends(requires(Permission.RULE_WRITE))):
    rule = session.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found")
    session.delete(rule)
    session.commit()
    audit.record(session, action="rule.delete", actor_id=user.id, target=rule_id)


# ── dashboard ───────────────────────────────────────────────────────────
@router.get("/stats")
def stats(session: Session = Depends(get_session), _: User = Depends(current_user)):
    day_ago = datetime.now(UTC) - timedelta(days=1)

    def count(model, *where):
        stmt = select(func.count()).select_from(model)
        for clause in where:
            stmt = stmt.where(clause)
        return session.exec(stmt).one()

    by_severity = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        by_severity[sev] = count(Alert, Alert.severity == sev, Alert.state == "open")

    techniques: list[str] = []
    for a in session.exec(select(Alert).limit(1000)).all():
        techniques.extend(t for t in a.mitre_techniques.split(",") if t)

    top = session.exec(
        select(Indicator).where(Indicator.is_active == True)  # noqa: E712
        .order_by(col(Indicator.hit_count).desc()).limit(5)
    ).all()

    return {
        "indicators": count(Indicator, Indicator.is_active == True),  # noqa: E712
        "events_24h": count(Event, Event.received_at >= day_ago),
        "alerts_open": count(Alert, Alert.state == "open"),
        "alerts_total": count(Alert),
        "rules_enabled": count(DetectionRule, DetectionRule.enabled == True),  # noqa: E712
        "by_severity": by_severity,
        "mitre_coverage": mitre.coverage(techniques),
        "top_indicators": [
            {"value": services.read_indicator(i, with_enrichment=False)["defanged"],
             "hits": i.hit_count, "type": i.ioc_type}
            for i in top
        ],
    }
