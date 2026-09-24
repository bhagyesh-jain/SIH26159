from typing import Optional, List, Any
from pydantic import BaseModel, ConfigDict


class EventResponse(BaseModel):
    id: str
    packet_number: int
    event_type: str
    timestamp: Optional[str] = None
    observed_json: Any

    model_config = ConfigDict(from_attributes=True)


class SessionResponse(BaseModel):
    id: str
    capture_id: str
    tcp_stream: int
    src: str
    dst: str
    src_port: int
    dst_port: int
    protocol: str
    completeness: str
    events_count: Optional[int] = 0

    model_config = ConfigDict(from_attributes=True)


class SessionDetailResponse(SessionResponse):
    events: List[EventResponse] = []
