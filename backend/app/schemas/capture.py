from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class CaptureResponse(BaseModel):
    id: str
    investigation_id: str
    filename: str
    sha256: str
    bytes: int
    format: str
    uploaded_at: datetime
    tshark_version: Optional[str] = None
    job_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
