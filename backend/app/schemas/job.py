from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class JobResponse(BaseModel):
    id: str
    capture_id: str
    state: str  # QUEUED, PROCESSING, COMPLETED, FAILED
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    error_code: Optional[str] = None
    parser_version: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
