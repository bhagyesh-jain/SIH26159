import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as DbSession
from backend.app.models.database import get_db, Session as DbSessionModel, Event, Capture, SecurityEvent, Finding
from backend.app.schemas.session import SessionResponse, SessionDetailResponse, EventResponse
from backend.app.schemas.security_event import SecurityEventResponse
from backend.app.schemas.finding import FindingResponse

router = APIRouter()


@router.get("/investigations/{investigation_id}/sessions", response_model=List[SessionResponse])
def list_investigation_sessions(investigation_id: str, db: DbSession = Depends(get_db)):
    """
    Returns all TCP streams/sessions extracted from captures belonging to an investigation.
    """
    captures = db.query(Capture).filter(Capture.investigation_id == investigation_id).all()
    capture_ids = [c.id for c in captures]

    if not capture_ids:
        return []

    sessions = db.query(DbSessionModel).filter(DbSessionModel.capture_id.in_(capture_ids)).all()
    
    result = []
    for s in sessions:
        s_res = SessionResponse.model_validate(s)
        s_res.events_count = db.query(Event).filter(Event.session_id == s.id).count()
        result.append(s_res)

    return result


@router.get("/sessions/{session_id}", response_model=SessionDetailResponse)
def get_session_detail(session_id: str, db: DbSession = Depends(get_db)):
    """
    Returns full packet event timeline and evidence for a specific TCP stream/session.
    """
    session = db.query(DbSessionModel).filter(DbSessionModel.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session stream not found.")

    events_db = db.query(Event).filter(Event.session_id == session_id).order_by(Event.packet_number.asc()).all()

    formatted_events = []
    for evt in events_db:
        parsed_obs = json.loads(evt.observed_json) if evt.observed_json else {}
        formatted_events.append(
            EventResponse(
                id=evt.id,
                packet_number=evt.packet_number,
                event_type=evt.event_type,
                timestamp=evt.timestamp,
                observed_json=parsed_obs
            )
        )

    res = SessionDetailResponse.model_validate(session)
    res.events = formatted_events
    res.events_count = len(formatted_events)
    return res


@router.get("/sessions/{session_id}/security-events", response_model=List[SecurityEventResponse])
def get_session_security_events(
    session_id: str,
    protocol: Optional[str] = Query(None, description="Filter by protocol (SMTP, IMAP, POP3, UNKNOWN)"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    upgrade_status: Optional[str] = Query(None, description="Filter by upgrade status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: DbSession = Depends(get_db)
):
    """
    Retrieves persisted security events for a specific session with optional filtering and pagination.
    """
    session = db.query(DbSessionModel).filter(DbSessionModel.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session stream not found.")

    query = db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id)
    if protocol:
        query = query.filter(SecurityEvent.protocol == protocol.upper())
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type.upper())
    if upgrade_status:
        query = query.filter(SecurityEvent.upgrade_status == upgrade_status.upper())

    events = query.offset(offset).limit(limit).all()
    return [SecurityEventResponse.from_db(evt) for evt in events]


@router.get("/sessions/{session_id}/findings", response_model=List[FindingResponse])
def get_session_findings(
    session_id: str,
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
    Retrieves persisted deterministic findings for a specific session with optional filtering and pagination.
    """
    session = db.query(DbSessionModel).filter(DbSessionModel.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session stream not found.")

    query = db.query(Finding).filter(Finding.session_id == session_id)
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
