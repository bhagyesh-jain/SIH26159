import json
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class SecurityEventResponse(BaseModel):
    id: str
    session_id: str
    event_type: str
    protocol: str
    upgrade_status: Optional[str] = None
    observed_value: str
    frame_numbers: Optional[List[int]] = None
    timestamp: Optional[str] = None
    evidence_source: str = "TSHARK_REASSEMBLED_STREAM"
    completeness_status: str = "COMPLETE"
    details: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_db(cls, evt: Any) -> "SecurityEventResponse":
        """Converts SQLAlchemy SecurityEvent model into Pydantic SecurityEventResponse schema."""
        frames = []
        if evt.frame_numbers:
            frames = [int(x.strip()) for x in evt.frame_numbers.split(",") if x.strip().isdigit()]

        details_dict = None
        if evt.details_json:
            try:
                details_dict = json.loads(evt.details_json)
            except Exception:
                details_dict = {}

        return cls(
            id=evt.id,
            session_id=evt.session_id,
            event_type=evt.event_type,
            protocol=evt.protocol,
            upgrade_status=evt.upgrade_status,
            observed_value=evt.observed_value,
            frame_numbers=frames,
            timestamp=str(evt.timestamp) if evt.timestamp is not None else None,
            evidence_source=evt.evidence_source,
            completeness_status=evt.completeness_status,
            details=details_dict,
        )
