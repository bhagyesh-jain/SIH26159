from typing import List, Optional
from pydantic import BaseModel, Field


class AnomalyResultItem(BaseModel):
    id: str
    investigation_id: str
    session_id: str
    tcp_stream: int
    protocol: str
    src: str
    dst: str
    src_port: int
    dst_port: int
    model_version: str = "isolation-forest-v1"
    feature_version: str = "features-v1"
    anomaly_score: int = Field(..., ge=0, le=100)
    anomaly_label: str  # ANOMALY, ELEVATED, NORMAL
    is_anomalous: bool
    confidence_band: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    evidence_state: str = "OBSERVED"  # OBSERVED, INCOMPLETE, UNKNOWN
    contributing_features: List[str] = Field(default_factory=list)
    supporting_finding_ids: List[str] = Field(default_factory=list)
    supporting_event_ids: List[str] = Field(default_factory=list)
    supporting_frame_numbers: List[int] = Field(default_factory=list)
    explanation: str
    created_at: Optional[str] = None


class AnomalySummary(BaseModel):
    total_sessions_analyzed: int = 0
    anomalous_sessions_count: int = 0
    elevated_sessions_count: int = 0
    normal_sessions_count: int = 0
    highest_anomaly_score: int = 0
    model_version: str = "isolation-forest-v1"
    feature_version: str = "features-v1"


class InvestigationAnomaliesResponse(BaseModel):
    investigation_id: str
    generated_at: str
    model_version: str = "isolation-forest-v1"
    feature_version: str = "features-v1"
    training_context: str = "Deterministic Pure-Python Isolation Forest baseline trained on structured evidence feature matrix"
    summary: AnomalySummary
    results: List[AnomalyResultItem] = Field(default_factory=list)
