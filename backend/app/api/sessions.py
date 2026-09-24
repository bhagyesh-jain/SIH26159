import json
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DbSession
from backend.app.models.database import get_db, Session as DbSessionModel, Event, Capture
from backend.app.schemas.session import SessionResponse, SessionDetailResponse, EventResponse

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
