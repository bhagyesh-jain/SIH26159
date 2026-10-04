import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, distinct, case
from sqlalchemy.orm import Session as DbSession
from backend.app.models.database import (
    get_db, Investigation, Capture, Session as DbSessionModel, SecurityEvent, Finding
)
from backend.app.schemas.investigation import (
    InvestigationCreate, InvestigationResponse, InvestigationSummaryResponse,
    InvestigationSummaryTotals, SeverityBreakdown, ProtocolBreakdown,
    SecurityPostureSummary, EvidenceQualitySummary, InvestigationReportResponse
)
from backend.app.schemas.security_event import SecurityEventResponse
from backend.app.schemas.finding import FindingResponse
from backend.app.schemas.capture import CaptureResponse
from backend.app.schemas.intelligence import InvestigationIntelligenceResponse
from backend.app.schemas.anomaly import InvestigationAnomaliesResponse
from backend.app.services.intelligence_service import compute_investigation_intelligence
from backend.app.services.ml_anomaly_service import compute_investigation_anomalies

router = APIRouter()


@router.post("/investigations", response_model=InvestigationResponse, status_code=201)
def create_investigation(payload: InvestigationCreate, db: DbSession = Depends(get_db)):
    """Creates a new forensic investigation case."""
    inv_id = f"inv_{uuid.uuid4().hex[:12]}"
    investigation = Investigation(
        id=inv_id,
        title=payload.title,
        status="ACTIVE"
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    return investigation


@router.get("/investigations", response_model=List[InvestigationResponse])
def list_investigations(db: DbSession = Depends(get_db)):
    """Lists all active forensic investigation cases."""
    return db.query(Investigation).order_by(Investigation.created_at.desc()).all()


@router.get("/investigations/{investigation_id}", response_model=InvestigationResponse)
def get_investigation(investigation_id: str, db: DbSession = Depends(get_db)):
    """Gets details for a specific investigation case."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation case not found.")
    return inv


@router.get("/investigations/{investigation_id}/summary", response_model=InvestigationSummaryResponse)
def get_investigation_summary(investigation_id: str, db: DbSession = Depends(get_db)):
    """
    Returns authoritative aggregated investigation metrics, severity distribution,
    protocol breakdowns, security posture indicators, and evidence quality summary.
    Performs server-side database SQL aggregation.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation case not found.")

    # 1. Capture & Session Totals
    captures_count = db.query(func.count(Capture.id)).filter(Capture.investigation_id == investigation_id).scalar() or 0
    
    capture_ids_subquery = db.query(Capture.id).filter(Capture.investigation_id == investigation_id)
    sessions_count = db.query(func.count(DbSessionModel.id)).filter(DbSessionModel.capture_id.in_(capture_ids_subquery)).scalar() or 0

    # 2. Protocol Breakdown
    protocol_rows = (
        db.query(DbSessionModel.protocol, func.count(DbSessionModel.id))
        .filter(DbSessionModel.capture_id.in_(capture_ids_subquery))
        .group_by(DbSessionModel.protocol)
        .all()
    )
    proto_map = {p: c for p, c in protocol_rows}

    # 3. Session Completeness Breakdown
    completeness_rows = (
        db.query(DbSessionModel.completeness, func.count(DbSessionModel.id))
        .filter(DbSessionModel.capture_id.in_(capture_ids_subquery))
        .group_by(DbSessionModel.completeness)
        .all()
    )
    comp_map = {c: count for c, count in completeness_rows}

    # 4. Finding Counts & Status Totals
    total_findings_count = db.query(func.count(Finding.id)).filter(Finding.investigation_id == investigation_id).scalar() or 0
    actionable_findings_count = db.query(func.count(Finding.id)).filter(
        Finding.investigation_id == investigation_id,
        Finding.severity != "INFO",
        Finding.status == "ACTIVE"
    ).scalar() or 0
    informational_findings_count = db.query(func.count(Finding.id)).filter(
        Finding.investigation_id == investigation_id,
        Finding.severity == "INFO"
    ).scalar() or 0
    suppressed_findings_count = db.query(func.count(Finding.id)).filter(
        Finding.investigation_id == investigation_id,
        Finding.status == "SUPPRESSED"
    ).scalar() or 0
    resolved_findings_count = db.query(func.count(Finding.id)).filter(
        Finding.investigation_id == investigation_id,
        Finding.status == "RESOLVED"
    ).scalar() or 0
    affected_sessions_count = db.query(func.count(distinct(Finding.session_id))).filter(
        Finding.investigation_id == investigation_id,
        Finding.severity != "INFO",
        Finding.status == "ACTIVE"
    ).scalar() or 0
    highest_risk_score = db.query(func.max(Finding.risk_score)).filter(
        Finding.investigation_id == investigation_id,
        Finding.status == "ACTIVE"
    ).scalar() or 0

    # 5. Severity Breakdown for ACTIVE Findings
    sev_rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.investigation_id == investigation_id, Finding.status == "ACTIVE")
        .group_by(Finding.severity)
        .all()
    )
    sev_map = {sev: count for sev, count in sev_rows}

    # 6. Security Posture Rule Counts (Distinct Session Count for ACTIVE Findings)
    rule_rows = (
        db.query(Finding.rule_id, func.count(distinct(Finding.session_id)))
        .filter(Finding.investigation_id == investigation_id, Finding.status == "ACTIVE")
        .group_by(Finding.rule_id)
        .all()
    )
    rule_map = {r: count for r, count in rule_rows}

    # 7. Finding Confidence Breakdown for ACTIVE Findings
    conf_rows = (
        db.query(Finding.confidence, func.count(Finding.id))
        .filter(Finding.investigation_id == investigation_id, Finding.status == "ACTIVE")
        .group_by(Finding.confidence)
        .all()
    )
    conf_map = {conf: count for conf, count in conf_rows}

    return InvestigationSummaryResponse(
        investigation_id=inv.id,
        title=inv.title,
        status=inv.status,
        created_at=inv.created_at,
        totals=InvestigationSummaryTotals(
            captures_count=captures_count,
            sessions_count=sessions_count,
            total_findings_count=total_findings_count,
            actionable_findings_count=actionable_findings_count,
            informational_findings_count=informational_findings_count,
            suppressed_findings_count=suppressed_findings_count,
            resolved_findings_count=resolved_findings_count,
            affected_sessions_count=affected_sessions_count,
            highest_risk_score=highest_risk_score,
        ),
        severity_breakdown=SeverityBreakdown(
            critical=sev_map.get("CRITICAL", 0),
            high=sev_map.get("HIGH", 0),
            medium=sev_map.get("MEDIUM", 0),
            low=sev_map.get("LOW", 0),
            info=sev_map.get("INFO", 0),
        ),
        protocol_breakdown=ProtocolBreakdown(
            smtp_sessions=proto_map.get("SMTP", 0),
            imap_sessions=proto_map.get("IMAP", 0),
            pop3_sessions=proto_map.get("POP3", 0),
            unknown_sessions=proto_map.get("UNKNOWN", 0),
        ),
        security_posture=SecurityPostureSummary(
            plaintext_not_offered_sessions=rule_map.get("EMAIL-PLAINTEXT-NOT-OFFERED-001", 0),
            starttls_offered_not_used_sessions=rule_map.get("EMAIL-STARTTLS-OFFERED-NOT-USED-001", 0),
            weak_static_rsa_sessions=rule_map.get("TLS-WEAK-STATIC-RSA-001", 0),
            certificate_alert_sessions=rule_map.get("TLS-ALERT-CERT-OBSERVED-001", 0),
            handshake_failed_sessions=rule_map.get("TLS-HANDSHAKE-FAILED-001", 0),
            secure_baseline_sessions=rule_map.get("TLS-SECURE-BASELINE-001", 0),
        ),
        evidence_quality=EvidenceQualitySummary(
            complete_sessions=comp_map.get("COMPLETE", 0),
            incomplete_sessions=comp_map.get("INCOMPLETE", 0),
            high_confidence_findings=conf_map.get("HIGH", 0),
            medium_confidence_findings=conf_map.get("MEDIUM", 0),
            low_or_unknown_confidence_findings=conf_map.get("LOW", 0) + conf_map.get("UNKNOWN", 0),
        ),
    )


@router.get("/investigations/{investigation_id}/report", response_model=InvestigationReportResponse)
def get_investigation_report(investigation_id: str, db: DbSession = Depends(get_db)):
    """
    Returns complete, authoritative forensic report dataset without pagination limits.
    Deterministic ordering: ACTIVE -> SUPPRESSED -> RESOLVED, risk_score DESC, id ASC.
    Includes full source captures provenance.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation case not found.")

    summary = get_investigation_summary(investigation_id, db)

    captures = db.query(Capture).filter(Capture.investigation_id == investigation_id).order_by(Capture.uploaded_at.desc()).all()
    capture_ids = [c.id for c in captures]

    captures_response = []
    for cap in captures:
        c_res = CaptureResponse.model_validate(cap)
        latest_job = cap.jobs[0] if cap.jobs else None
        if latest_job:
            c_res.job_id = latest_job.id
            c_res.status = latest_job.state
        else:
            c_res.status = "COMPLETED"
        c_res.sessions_count = len(cap.sessions)
        captures_response.append(c_res)

    if not capture_ids:
        return InvestigationReportResponse(
            investigation_id=inv.id,
            title=inv.title,
            status=inv.status,
            created_at=inv.created_at,
            generated_at=datetime.utcnow(),
            evidence_scope="COMPLETE",
            summary=summary,
            captures=captures_response,
            findings=[],
            security_events=[],
        )

    sessions = db.query(DbSessionModel).filter(DbSessionModel.capture_id.in_(capture_ids)).all()
    session_ids = [s.id for s in sessions]

    if not session_ids:
        return InvestigationReportResponse(
            investigation_id=inv.id,
            title=inv.title,
            status=inv.status,
            created_at=inv.created_at,
            generated_at=datetime.utcnow(),
            evidence_scope="COMPLETE",
            summary=summary,
            captures=captures_response,
            findings=[],
            security_events=[],
        )

    # Status Ordering: ACTIVE (1), SUPPRESSED (2), RESOLVED (3)
    status_order = case(
        (Finding.status == "ACTIVE", 1),
        (Finding.status == "SUPPRESSED", 2),
        else_=3
    )

    findings = (
        db.query(Finding)
        .filter(Finding.session_id.in_(session_ids))
        .order_by(status_order, Finding.risk_score.desc(), Finding.id.asc())
        .all()
    )

    events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.session_id.in_(session_ids))
        .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc())
        .all()
    )

    evidence_scope = "INCOMPLETE" if summary.evidence_quality.incomplete_sessions > 0 else "COMPLETE"

    return InvestigationReportResponse(
        investigation_id=inv.id,
        title=inv.title,
        status=inv.status,
        created_at=inv.created_at,
        generated_at=datetime.utcnow(),
        evidence_scope=evidence_scope,
        summary=summary,
        captures=captures_response,
        findings=[FindingResponse.from_db(f) for f in findings],
        security_events=[SecurityEventResponse.from_db(evt) for evt in events],
    )


@router.get("/investigations/{investigation_id}/security-events", response_model=List[SecurityEventResponse])
def get_investigation_security_events(
    investigation_id: str,
    protocol: Optional[str] = Query(None, description="Filter by protocol (SMTP, IMAP, POP3, UNKNOWN)"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    upgrade_status: Optional[str] = Query(None, description="Filter by upgrade status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: DbSession = Depends(get_db)
):
    """
    Retrieves all persisted security events across all captures and sessions belonging to an investigation.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation case not found.")

    captures = db.query(Capture).filter(Capture.investigation_id == investigation_id).all()
    capture_ids = [c.id for c in captures]

    if not capture_ids:
        return []

    sessions = db.query(DbSessionModel).filter(DbSessionModel.capture_id.in_(capture_ids)).all()
    session_ids = [s.id for s in sessions]

    if not session_ids:
        return []

    query = db.query(SecurityEvent).filter(SecurityEvent.session_id.in_(session_ids))
    if protocol:
        query = query.filter(SecurityEvent.protocol == protocol.upper())
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type.upper())
    if upgrade_status:
        query = query.filter(SecurityEvent.upgrade_status == upgrade_status.upper())

    events = query.offset(offset).limit(limit).all()
    return [SecurityEventResponse.from_db(evt) for evt in events]


@router.get("/investigations/{investigation_id}/findings", response_model=List[FindingResponse])
def get_investigation_findings(
    investigation_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    confidence: Optional[str] = Query(None, description="Filter by confidence (HIGH, MEDIUM, LOW, UNKNOWN)"),
    protocol: Optional[str] = Query(None, description="Filter by protocol (SMTP, IMAP, POP3, UNKNOWN)"),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    status: Optional[str] = Query(None, description="Filter by status (ACTIVE, RESOLVED, SUPPRESSED)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: DbSession = Depends(get_db)
):
    """
    Retrieves all persisted deterministic findings across all captures and sessions belonging to an investigation.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation case not found.")

    captures = db.query(Capture).filter(Capture.investigation_id == investigation_id).all()
    capture_ids = [c.id for c in captures]

    if not capture_ids:
        return []

    sessions = db.query(DbSessionModel).filter(DbSessionModel.capture_id.in_(capture_ids)).all()
    session_ids = [s.id for s in sessions]

    if not session_ids:
        return []

    query = db.query(Finding).filter(Finding.session_id.in_(session_ids))
    if severity:
        query = query.filter(Finding.severity == severity.upper())
    if confidence:
        query = query.filter(Finding.confidence == confidence.upper())
    if protocol:
        query = query.filter(Finding.protocol == protocol.upper())
    if rule_id:
        query = query.filter(Finding.rule_id == rule_id)
    if status:
        query = query.filter(Finding.status == status.upper())

    findings = query.order_by(Finding.risk_score.desc(), Finding.id.asc()).offset(offset).limit(limit).all()
    return [FindingResponse.from_db(f) for f in findings]


@router.get("/investigations/{investigation_id}/intelligence", response_model=InvestigationIntelligenceResponse)
def get_investigation_intelligence(investigation_id: str, db: DbSession = Depends(get_db)):
    """
    Returns deterministic, explainable security intelligence and correlation patterns
    for an investigation case.
    """
    intel = compute_investigation_intelligence(investigation_id, db)
    if not intel:
        raise HTTPException(status_code=404, detail="Investigation case not found.")
    return intel


@router.get("/investigations/{investigation_id}/anomalies", response_model=InvestigationAnomaliesResponse)
def get_investigation_anomalies(investigation_id: str, db: DbSession = Depends(get_db)):
    """
    Returns ML-assisted anomaly detection results and explainable feature attributions
    for an investigation case.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation case not found.")

    return compute_investigation_anomalies(db, investigation_id)

