import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as DbSession
from backend.app.models.database import (
    get_db, Investigation, Capture, Session as DbSessionModel, SecurityEvent, Finding
)
from backend.app.schemas.investigation import InvestigationCreate, InvestigationResponse
from backend.app.schemas.security_event import SecurityEventResponse
from backend.app.schemas.finding import FindingResponse

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

    findings = query.order_by(Finding.risk_score.desc()).offset(offset).limit(limit).all()
    return [FindingResponse.from_db(f) for f in findings]
