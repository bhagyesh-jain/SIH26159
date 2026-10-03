import json
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class FindingResponse(BaseModel):
    id: str
    investigation_id: str
    session_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    risk_score: int
    status: str = "ACTIVE"
    protocol: str
    observed_value: str
    evidence_event_ids: List[str]
    evidence_frame_numbers: List[int]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_db(cls, db_obj: Any) -> "FindingResponse":
        """Converts SQLAlchemy Finding model into typed FindingResponse schema."""
        event_ids = []
        if db_obj.evidence_event_ids:
            try:
                event_ids = json.loads(db_obj.evidence_event_ids)
            except Exception:
                event_ids = []

        frame_numbers = []
        if db_obj.evidence_frame_numbers:
            try:
                frame_numbers = json.loads(db_obj.evidence_frame_numbers)
            except Exception:
                frame_numbers = []

        details_dict = None
        if db_obj.details_json:
            try:
                details_dict = json.loads(db_obj.details_json)
            except Exception:
                details_dict = {}

        return cls(
            id=db_obj.id,
            investigation_id=db_obj.investigation_id,
            session_id=db_obj.session_id,
            rule_id=db_obj.rule_id,
            title=db_obj.title,
            description=db_obj.description,
            severity=db_obj.severity,
            confidence=db_obj.confidence,
            risk_score=db_obj.risk_score,
            status=db_obj.status,
            protocol=db_obj.protocol,
            observed_value=db_obj.observed_value,
            evidence_event_ids=event_ids,
            evidence_frame_numbers=frame_numbers,
            first_seen=db_obj.first_seen,
            last_seen=db_obj.last_seen,
            details=details_dict
        )
