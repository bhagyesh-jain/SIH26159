from datetime import datetime
from pydantic import BaseModel, ConfigDict


class InvestigationCreate(BaseModel):
    title: str


class InvestigationResponse(BaseModel):
    id: str
    title: str
    created_at: datetime
    status: str

    model_config = ConfigDict(from_attributes=True)
