from typing import List, Optional, Dict
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from backend.app.schemas.investigation import SeverityBreakdown


class IntelligenceInsight(BaseModel):
    id: str
    title: str
    description: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    confidence: str  # "HIGH", "MEDIUM", "LOW"
    risk_score: int
    evidence_state: str  # "OBSERVED", "OBSERVED_BASELINE", "INCOMPLETE", "UNKNOWN"
    supporting_finding_ids: List[str] = []
    supporting_session_ids: List[str] = []
    supporting_event_ids: List[str] = []
    supporting_frame_numbers: List[int] = []
    remediation: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class RiskSummaryIntelligence(BaseModel):
    highest_risk_score: int
    highest_risk_finding_id: Optional[str] = None
    highest_risk_session_id: Optional[str] = None
    active_findings_count: int
    affected_sessions_count: int
    risk_concentration: Dict[str, int] = {}

    model_config = ConfigDict(from_attributes=True)


class ProtocolExposureItem(BaseModel):
    protocol: str  # "SMTP", "IMAP", "POP3", "UNKNOWN"
    total_sessions: int
    affected_sessions: int
    active_findings_count: int
    highest_risk_score: int
    severity_breakdown: SeverityBreakdown
    dominant_rule_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PatternSummary(BaseModel):
    repeated_rules: List[str] = []
    affected_protocols: List[str] = []
    affected_sessions_count: int

    model_config = ConfigDict(from_attributes=True)


class InvestigationIntelligenceResponse(BaseModel):
    investigation_id: str
    generated_at: datetime
    risk_summary: RiskSummaryIntelligence
    protocol_exposure: List[ProtocolExposureItem]
    pattern_summary: PatternSummary
    insights: List[IntelligenceInsight]

    model_config = ConfigDict(from_attributes=True)
