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


class InvestigationSummaryTotals(BaseModel):
    captures_count: int
    sessions_count: int
    total_findings_count: int
    actionable_findings_count: int
    informational_findings_count: int
    suppressed_findings_count: int
    resolved_findings_count: int
    affected_sessions_count: int
    highest_risk_score: int


class SeverityBreakdown(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int


class ProtocolBreakdown(BaseModel):
    smtp_sessions: int
    imap_sessions: int
    pop3_sessions: int
    unknown_sessions: int


class SecurityPostureSummary(BaseModel):
    plaintext_not_offered_sessions: int
    starttls_offered_not_used_sessions: int
    weak_static_rsa_sessions: int
    certificate_alert_sessions: int
    handshake_failed_sessions: int
    secure_baseline_sessions: int


class EvidenceQualitySummary(BaseModel):
    complete_sessions: int
    incomplete_sessions: int
    high_confidence_findings: int
    medium_confidence_findings: int
    low_or_unknown_confidence_findings: int


class InvestigationSummaryResponse(BaseModel):
    investigation_id: str
    title: str
    status: str
    created_at: datetime
    totals: InvestigationSummaryTotals
    severity_breakdown: SeverityBreakdown
    protocol_breakdown: ProtocolBreakdown
    security_posture: SecurityPostureSummary
    evidence_quality: EvidenceQualitySummary

    model_config = ConfigDict(from_attributes=True)
