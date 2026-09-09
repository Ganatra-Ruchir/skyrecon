"""
Application services: the pipeline that turns raw input into triaged signal.

Handlers stay thin; this is where encryption, deduplication, scoring, rule
evaluation and alert creation actually happen.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, col, select

from app import audit, intel_live
from app.config import get_settings
from app.detect import mitre, rules
from app.detect.anomaly import AnomalyModel
from app.ioc import enrich as enrich_mod
from app.ioc import parser, scoring
from app.ioc.observable import LABELS as OBSERVABLE_LABELS
from app.ioc.observable import detect_observable
from app.models import Alert, DetectionRule, Event, Indicator, IndicatorSnapshot, IOCType, utcnow
from app.security.crypto import FieldContext, get_vault

# One model per process, refit as telemetry accumulates.
_anomaly = AnomalyModel()
_anomaly_fitted_at = 0


# ── indicators ──────────────────────────────────────────────────────────
def upsert_indicator(
    session: Session, *, value: str, ioc_type: IOCType | None = None,
    source: str = "manual", severity: str = "medium", confidence: int = 50,
    tags: list[str] | None = None, tlp: str = "amber", notes: str | None = None,
    actor_id: str | None = None,
) -> tuple[Indicator, bool]:
    """Create or reinforce an indicator. Returns (record, created)."""
    vault = get_vault()
    resolved = ioc_type or parser.detect_type(value)
    if resolved is None:
        raise ValueError(f"could not classify {value!r} as an indicator")

    clean = parser.normalize(parser.refang(value), resolved)
    if not parser.validate(clean, resolved):
        raise ValueError(f"{clean!r} is not a valid {resolved.value} indicator")

    index = vault.blind_index(clean, "indicator")
    existing = session.exec(
        select(Indicator).where(Indicator.value_index == index)
    ).first()

    if existing:
        existing.hit_count += 1
        existing.last_seen = utcnow()
        existing.confidence = scoring.reinforce(existing.confidence, source=source)
        if tags:
            merged = {t for t in existing.tags.split(",") if t} | set(tags)
            existing.tags = ",".join(sorted(merged))
        existing.is_active = True
        session.add(existing)
        session.commit()
        session.refresh(existing)
        audit.record(session, action="ioc.reinforce", actor_id=actor_id,
                     target=existing.id, detail={"source": source})
        return existing, False

    record = Indicator(
        value_index=index, value_sealed="", ioc_type=resolved.value, source=source,
        confidence=max(0, min(100, confidence)), severity=severity,
        tags=",".join(sorted(set(tags or []))), tlp=tlp, created_by=actor_id,
    )
    record.value_sealed = vault.seal(
        clean, FieldContext("indicators", "value", record.id)
    )
    if notes:
        record.notes_sealed = vault.seal(
            notes, FieldContext("indicators", "notes", record.id)
        )
    session.add(record)
    session.commit()
    session.refresh(record)
    audit.record(session, action="ioc.create", actor_id=actor_id,
                 target=record.id, detail={"type": resolved.value, "source": source})
    return record, True


def read_indicator(record: Indicator, *, with_enrichment: bool = True) -> dict:
    """Decrypt one indicator into an API-shaped dict."""
    vault = get_vault()
    value = vault.open(record.value_sealed, FieldContext("indicators", "value", record.id))
    notes = vault.open(record.notes_sealed, FieldContext("indicators", "notes", record.id))
    settings = get_settings()

    effective = scoring.decayed_confidence(
        record.confidence, record.last_seen, half_life_days=settings.ioc_half_life_days
    )
    enrichment = None
    modifier = 0.0
    if with_enrichment and value:
        e = enrich_mod.enrich(value, IOCType(record.ioc_type))
        enrichment = e.as_dict()
        modifier = e.risk_modifier

    base = scoring.risk_score(
        confidence=effective, severity=record.severity, source=record.source,
        corroborations=record.hit_count,
    )
    risk = round(max(0.0, min(100.0, base * (1 + modifier * 0.35))), 1)

    parsed = parser.ParsedIOC(value=value or "", ioc_type=IOCType(record.ioc_type))
    return {
        "id": record.id, "value": value, "defanged": parsed.defanged(),
        "ioc_type": record.ioc_type, "source": record.source,
        "severity": record.severity, "confidence": record.confidence,
        "effective_confidence": effective, "risk_score": risk,
        "tags": [t for t in record.tags.split(",") if t], "tlp": record.tlp,
        "notes": notes, "enrichment": enrichment,
        "first_seen": record.first_seen, "last_seen": record.last_seen,
        "hit_count": record.hit_count, "is_active": record.is_active,
    }


def universal_search(session: Session, query: str) -> dict:
    """
    Classify one pasted value and, if it's a type SkyRecon actually stores,
    say whether it's already in the database. Never guesses at types it
    can't back with real data — an unsupported observable is labeled as
    such, not silently dropped or faked as a full lookup.
    """
    q = (query or "").strip()
    if not q:
        return {"query": q, "detected_type": None, "supported": False, "stored": None}

    ioc_type = parser.detect_type(q)
    if ioc_type is not None:
        clean = parser.normalize(parser.refang(q), ioc_type)
        vault = get_vault()
        index = vault.blind_index(clean, "indicator")
        existing = session.exec(select(Indicator).where(Indicator.value_index == index)).first()
        return {
            "query": q, "detected_type": ioc_type.value, "normalized": clean,
            "supported": True, "stored": read_indicator(existing) if existing else None,
        }

    observable = detect_observable(q)
    if observable:
        return {
            "query": q, "detected_type": OBSERVABLE_LABELS[observable], "normalized": q,
            "supported": False, "stored": None,
        }

    return {"query": q, "detected_type": None, "normalized": q, "supported": False, "stored": None}


def _snapshot_history(session: Session, indicator_id: str) -> dict:
    """Distinct values seen across every deep-enrich snapshot so far — the
    only "history" honestly available without a paid passive-DNS provider:
    it starts the day this feature shipped, not before."""
    past = session.exec(
        select(IndicatorSnapshot)
        .where(IndicatorSnapshot.indicator_id == indicator_id)
        .order_by(col(IndicatorSnapshot.taken_at))
    ).all()
    return {
        "observations": len(past),
        "since": past[0].taken_at if past else None,
        "distinct_ips": sorted({ip for s in past for ip in s.resolved_ips.split(",") if ip}),
        "distinct_nameservers": sorted({ns for s in past for ns in s.nameservers.split(",") if ns}),
        "distinct_certs": sorted({f"{s.cert_issuer} (#{s.cert_serial})" for s in past
                                   if s.cert_issuer}),
    }


def deep_enrich_indicator(session: Session, record: Indicator, *, actor_id: str | None = None) -> dict:
    """
    Live, passive lookups (RDAP, DNS, certificate transparency) for one
    indicator, plus the infrastructure history this system has itself
    observed across past calls.

    Unlike read_indicator's enrichment, this leaves the network — every call
    goes to a public registry, resolver or log, never to the indicator's own
    infrastructure. Audited so there is a record of when the system reached
    out about a specific indicator.
    """
    vault = get_vault()
    value = vault.open(record.value_sealed, FieldContext("indicators", "value", record.id))
    ioc_type = IOCType(record.ioc_type)

    if not value:
        return {}

    out: dict = {}
    snap = IndicatorSnapshot(indicator_id=record.id)

    if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
        rdap = intel_live.rdap_ip(value)
        out["rdap"] = rdap
        snap.resolved_ips = value
        snap.network_org = rdap.get("network_org")
    elif ioc_type in {IOCType.DOMAIN, IOCType.URL, IOCType.EMAIL}:
        if ioc_type is IOCType.URL:
            host = value.lower().split("://", 1)[-1].split("/")[0].split(":")[0]
        elif ioc_type is IOCType.EMAIL:
            host = value.split("@")[-1]
        else:
            host = value
        out["rdap"] = intel_live.rdap_domain(host)
        out["dns"] = intel_live.dns_records(host)
        out["certificates"] = intel_live.cert_transparency(host)
        snap.resolved_ips = ",".join(out["dns"].get("A", []) + out["dns"].get("AAAA", []))
        snap.nameservers = ",".join(out["rdap"].get("nameservers") or out["dns"].get("NS", []))
        current_cert = out["certificates"].get("current_cert") or {}
        snap.cert_issuer = current_cert.get("issuer")
        snap.cert_serial = current_cert.get("serial")

    out = {k: v for k, v in out.items() if v}
    if snap.resolved_ips or snap.nameservers or snap.cert_issuer:
        session.add(snap)
        session.commit()
    out["history"] = _snapshot_history(session, record.id)

    audit.record(session, action="ioc.deep_enrich", actor_id=actor_id, target=record.id,
                 detail={"ioc_type": ioc_type.value, "found": list(out.keys())})
    return out


def bulk_ingest(
    session: Session, *, text: str, source: str, severity: str,
    tags: list[str], actor_id: str | None = None,
) -> dict:
    """Extract every indicator from a report and store what is genuinely new."""
    found = parser.extract(text)
    created, reinforced, rejected = [], [], []
    for item in found:
        try:
            _record, is_new = upsert_indicator(
                session, value=item.value, ioc_type=item.ioc_type, source=source,
                severity=severity, tags=tags, actor_id=actor_id,
            )
            (created if is_new else reinforced).append(item.value)
        except ValueError as exc:
            rejected.append({"value": item.value, "reason": str(exc)})
    audit.record(session, action="ioc.bulk_ingest", actor_id=actor_id,
                 detail={"found": len(found), "created": len(created)})
    return {
        "extracted": len(found), "created": created,
        "reinforced": reinforced, "rejected": rejected,
    }


# ── events → detection → alerts ─────────────────────────────────────────
def _match_indicators(session: Session, payload: str) -> list[Indicator]:
    """Every stored indicator that literally appears in this payload."""
    vault = get_vault()
    hits: list[Indicator] = []
    for parsed in parser.extract(payload, keep_noise=True):
        index = vault.blind_index(parsed.value, "indicator")
        found = session.exec(
            select(Indicator).where(
                Indicator.value_index == index, Indicator.is_active == True  # noqa: E712
            )
        ).first()
        if found:
            hits.append(found)
    return hits


def _facts_for(event: Event, payload: str, indicator: Indicator | None) -> dict:
    facts = {
        "payload": payload, "source": event.source, "kind": event.kind,
        "bytes_out": event.bytes_out, "bytes_in": event.bytes_in,
        "duration_ms": event.duration_ms, "risk": event.risk_score,
        "severity": "medium", "confidence": 0, "ioc_type": "",
        "dga": 0.0, "tld_risk": 0.0, "entropy": 0.0, "tags": "",
        "internal": False,
    }
    if indicator:
        info = read_indicator(indicator)
        signals = (info.get("enrichment") or {}).get("signals", {})
        facts.update({
            "severity": info["severity"], "confidence": info["effective_confidence"],
            "ioc_type": info["ioc_type"], "tags": ",".join(info["tags"]),
            "dga": float(signals.get("dga_likelihood") or 0.0),
            "tld_risk": float(signals.get("tld_risk") or 0.0),
            "entropy": float(signals.get("entropy") or 0.0),
            "risk": info["risk_score"],
        })
    return facts


def ingest_event(
    session: Session, *, source: str, kind: str, payload: str,
    src_ip: str | None = None, dst_ip: str | None = None,
    bytes_out: int = 0, bytes_in: int = 0, duration_ms: int = 0,
    actor_id: str | None = None,
) -> dict:
    """Store an observation, run detection over it, raise alerts."""
    vault = get_vault()
    event = Event(
        source=source, kind=kind, payload_sealed="", bytes_out=bytes_out,
        bytes_in=bytes_in, duration_ms=duration_ms,
        src_ip_index=vault.blind_index(src_ip, "ip") if src_ip else None,
        dst_ip_index=vault.blind_index(dst_ip, "ip") if dst_ip else None,
    )
    event.payload_sealed = vault.seal(
        payload, FieldContext("events", "payload", event.id)
    )
    event.src_ip_sealed = vault.seal(src_ip, FieldContext("events", "src_ip", event.id))
    event.dst_ip_sealed = vault.seal(dst_ip, FieldContext("events", "dst_ip", event.id))
    session.add(event)
    session.commit()
    session.refresh(event)

    matched = _match_indicators(session, payload)
    alerts: list[Alert] = []

    # 1. indicator hits
    for indicator in matched:
        info = read_indicator(indicator)
        indicator.hit_count += 1
        indicator.last_seen = utcnow()
        session.add(indicator)
        alert = _raise_alert(
            session,
            title=f"Known indicator observed: {info['defanged']}",
            severity=info["severity"], score=info["risk_score"],
            event_id=event.id, indicator_id=indicator.id,
            techniques="T1071.001",
            detail={"indicator": info["defanged"], "type": info["ioc_type"],
                    "confidence": info["effective_confidence"],
                    "reasons": (info.get("enrichment") or {}).get("reasons", [])},
        )
        alerts.append(alert)

    # 2. rule matches
    active_rules = session.exec(
        select(DetectionRule).where(DetectionRule.enabled == True)  # noqa: E712
    ).all()
    primary = matched[0] if matched else None
    facts = _facts_for(event, payload, primary)
    for rule in active_rules:
        try:
            if not rules.evaluate(rule.expression, facts):
                continue
        except rules.RuleError:
            continue  # a broken rule must never break ingestion
        rule.hit_count += 1
        rule.updated_at = utcnow()
        session.add(rule)
        alerts.append(_raise_alert(
            session, title=f"Rule matched: {rule.name}", severity=rule.severity,
            score=scoring.risk_score(confidence=70, severity=rule.severity, source=source),
            event_id=event.id, rule_id=rule.id, techniques=rule.mitre_techniques,
            detail={"rule": rule.name, "description": rule.description},
        ))

    # 3. statistical anomaly
    anomaly_score, reasons = _score_anomaly(session, event, payload)
    if anomaly_score >= 0.85:
        alerts.append(_raise_alert(
            session, title="Behavioural anomaly in event telemetry",
            severity="medium", score=round(anomaly_score * 70, 1),
            event_id=event.id, techniques="T1030",
            detail={"anomaly": anomaly_score, "reasons": reasons},
        ))

    event.risk_score = max([a.score for a in alerts], default=round(anomaly_score * 40, 1))
    session.add(event)
    session.commit()

    audit.record(session, action="event.ingest", actor_id=actor_id, target=event.id,
                 detail={"alerts": len(alerts), "matched": len(matched)})

    return {
        "id": event.id, "received_at": event.received_at, "source": event.source,
        "kind": event.kind, "payload": payload, "risk_score": event.risk_score,
        "matched_indicators": [i.id for i in matched],
        "alerts_created": [a.id for a in alerts],
        "anomaly": anomaly_score, "anomaly_reasons": reasons,
    }


#: an open alert for the same cause inside this window is counted, not repeated
DEDUPE_WINDOW_MINUTES = 30


def _raise_alert(
    session: Session, *, title: str, severity: str, score: float,
    event_id: str | None = None, indicator_id: str | None = None,
    rule_id: str | None = None, techniques: str = "", detail: dict | None = None,
) -> Alert:
    # One cause, one alert. Repeats increment a counter so an analyst sees
    # "47 occurrences" instead of 47 rows hiding the one that matters.
    vault = get_vault()
    key = vault.blind_index(
        f"{rule_id or '-'}|{indicator_id or '-'}|{title[:120]}", "alert-dedupe"
    )
    cutoff = datetime.now(UTC) - timedelta(minutes=DEDUPE_WINDOW_MINUTES)
    existing = session.exec(
        select(Alert).where(
            Alert.dedupe_index == key,
            Alert.state == "open",
            Alert.last_seen_at >= cutoff,
        ).order_by(col(Alert.last_seen_at).desc())
    ).first()
    if existing is not None:
        existing.occurrences += 1
        existing.last_seen_at = utcnow()
        existing.score = max(existing.score, score)
        if event_id:
            existing.event_id = event_id
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing

    alert = Alert(
        dedupe_index=key, title_sealed="", severity=severity, score=score,
        event_id=event_id, indicator_id=indicator_id, rule_id=rule_id,
        mitre_techniques=techniques,
    )
    alert.title_sealed = vault.seal(
        title[:300], FieldContext("alerts", "title", alert.id)
    )
    if detail:
        alert.detail_sealed = vault.seal(
            json.dumps(detail, default=str), FieldContext("alerts", "detail", alert.id)
        )
    session.add(alert)
    session.commit()
    session.refresh(alert)
    return alert


def _score_anomaly(session: Session, event: Event, payload: str) -> tuple[float, list[str]]:
    global _anomaly_fitted_at
    total = session.exec(select(Event)).all()
    if len(total) - _anomaly_fitted_at >= 25 or not _anomaly.is_trained:
        vault = get_vault()
        sample = []
        for e in total[-500:]:
            try:
                text = vault.open(e.payload_sealed, FieldContext("events", "payload", e.id))
            except Exception:
                text = ""
            sample.append({"bytes_out": e.bytes_out, "bytes_in": e.bytes_in,
                           "duration_ms": e.duration_ms, "received_at": e.received_at,
                           "payload": text})
        if sample:
            _anomaly.fit(sample)
            _anomaly_fitted_at = len(total)

    probe = {"bytes_out": event.bytes_out, "bytes_in": event.bytes_in,
             "duration_ms": event.duration_ms, "received_at": event.received_at,
             "payload": payload}
    if not _anomaly.is_trained:
        return 0.0, []
    return _anomaly.score(probe), _anomaly.explain(probe)


def read_alert(alert: Alert) -> dict:
    vault = get_vault()
    detail = None
    if alert.detail_sealed:
        try:
            raw = vault.open(alert.detail_sealed, FieldContext("alerts", "detail", alert.id))
            detail = json.loads(raw) if raw else None
        except Exception:
            detail = None
    try:
        title = vault.open(alert.title_sealed, FieldContext("alerts", "title", alert.id))
    except Exception:
        title = "<unreadable: key mismatch>"
    return {
        "id": alert.id, "created_at": alert.created_at, "title": title,
        "occurrences": alert.occurrences,
        "severity": alert.severity, "state": alert.state, "score": alert.score,
        "rule_id": alert.rule_id, "event_id": alert.event_id,
        "indicator_id": alert.indicator_id,
        "mitre": mitre.describe(alert.mitre_techniques), "detail": detail,
        "assigned_to": alert.assigned_to, "resolved_at": alert.resolved_at,
    }


def seed_builtin_rules(session: Session) -> int:
    added = 0
    for spec in rules.BUILTIN_RULES:
        exists = session.exec(
            select(DetectionRule).where(DetectionRule.name == spec["name"])
        ).first()
        if exists:
            continue
        ok, err = rules.validate_expression(spec["expression"])
        if not ok:
            raise RuntimeError(f"built-in rule {spec['name']!r} is invalid: {err}")
        session.add(DetectionRule(**spec))
        added += 1
    session.commit()
    return added
