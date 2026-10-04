export interface InvestigationCreate {
  title: string;
}

export interface InvestigationResponse {
  id: string;
  title: string;
  created_at: string;
  status: string;
}

export interface CaptureResponse {
  id: string;
  investigation_id: string;
  filename: string;
  sha256: string;
  bytes: number;
  format: string;
  uploaded_at: string;
  tshark_version?: string | null;
  job_id?: string | null;
  status?: JobState | string | null;
  sessions_count?: number;
}

export type JobState = "QUEUED" | "PROCESSING" | "COMPLETED" | "FAILED";

export interface JobResponse {
  id: string;
  capture_id: string;
  state: JobState;
  started_at?: string | null;
  ended_at?: string | null;
  error_code?: string | null;
  parser_version?: string | null;
}

export interface SessionResponse {
  id: string;
  capture_id: string;
  tcp_stream: number;
  src: string;
  dst: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  completeness: string;
  events_count?: number;
  capture_filename?: string | null;
  capture_sha256?: string | null;
}

export interface EventResponse {
  id: string;
  packet_number: number;
  event_type: string;
  timestamp?: string | null;
  observed_json: Record<string, unknown> | unknown;
}

export interface SessionDetailResponse extends SessionResponse {
  events: EventResponse[];
}

export interface SecurityEventResponse {
  id: string;
  session_id: string;
  event_type: string;
  protocol: string;
  upgrade_status?: string | null;
  observed_value: string;
  frame_numbers?: number[] | null;
  timestamp?: string | null;
  evidence_source: string;
  completeness_status: string;
  details?: Record<string, unknown> | null;
}

export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type FindingConfidence = "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type FindingStatus = "ACTIVE" | "RESOLVED" | "SUPPRESSED";
export type ForensicProtocol = "SMTP" | "IMAP" | "POP3" | "UNKNOWN";

export interface FindingResponse {
  id: string;
  investigation_id: string;
  session_id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  risk_score: number;
  status: FindingStatus;
  protocol: ForensicProtocol;
  observed_value: string;
  evidence_event_ids: string[];
  evidence_frame_numbers: number[];
  first_seen?: string | null;
  last_seen?: string | null;
  details?: Record<string, unknown> | null;
}

export interface HealthResponse {
  status: string;
  tshark: {
    available: boolean;
    version: string;
  };
}

export interface SecurityEventQueryParams {
  protocol?: string;
  event_type?: string;
  upgrade_status?: string;
  limit?: number;
  offset?: number;
}

export interface FindingQueryParams {
  severity?: FindingSeverity;
  confidence?: FindingConfidence;
  protocol?: ForensicProtocol | string;
  rule_id?: string;
  status?: FindingStatus | string;
  limit?: number;
  offset?: number;
}

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ProtocolBreakdown {
  smtp_sessions: number;
  imap_sessions: number;
  pop3_sessions: number;
  unknown_sessions: number;
}

export interface SecurityPostureSummary {
  plaintext_not_offered_sessions: number;
  starttls_offered_not_used_sessions: number;
  weak_static_rsa_sessions: number;
  certificate_alert_sessions: number;
  handshake_failed_sessions: number;
  secure_baseline_sessions: number;
}

export interface EvidenceQualitySummary {
  complete_sessions: number;
  incomplete_sessions: number;
  high_confidence_findings: number;
  medium_confidence_findings: number;
  low_or_unknown_confidence_findings: number;
}

export interface InvestigationSummaryTotals {
  captures_count: number;
  sessions_count: number;
  total_findings_count: number;
  actionable_findings_count: number;
  informational_findings_count: number;
  suppressed_findings_count: number;
  resolved_findings_count: number;
  affected_sessions_count: number;
  highest_risk_score: number;
}

export interface InvestigationSummaryResponse {
  investigation_id: string;
  title: string;
  status: string;
  created_at: string;
  totals: InvestigationSummaryTotals;
  severity_breakdown: SeverityBreakdown;
  protocol_breakdown: ProtocolBreakdown;
  security_posture: SecurityPostureSummary;
  evidence_quality: EvidenceQualitySummary;
}

export interface InvestigationReportResponse {
  investigation_id: string;
  title: string;
  status: string;
  created_at: string;
  generated_at: string;
  evidence_scope: "COMPLETE" | "INCOMPLETE" | string;
  summary: InvestigationSummaryResponse;
  captures: CaptureResponse[];
  findings: FindingResponse[];
  security_events: SecurityEventResponse[];
}

export interface IntelligenceInsight {
  id: string;
  title: string;
  description: string;
  severity: FindingSeverity | string;
  confidence: FindingConfidence | string;
  risk_score: number;
  evidence_state: "OBSERVED" | "OBSERVED_BASELINE" | "INCOMPLETE" | "UNKNOWN" | string;
  supporting_finding_ids: string[];
  supporting_session_ids: string[];
  supporting_event_ids: string[];
  supporting_frame_numbers: number[];
  remediation?: string | null;
}

export interface RiskSummaryIntelligence {
  highest_risk_score: number;
  highest_risk_finding_id?: string | null;
  highest_risk_session_id?: string | null;
  active_findings_count: number;
  affected_sessions_count: number;
  risk_concentration: Record<string, number>;
}

export interface ProtocolExposureItem {
  protocol: string;
  total_sessions: number;
  affected_sessions: number;
  active_findings_count: number;
  highest_risk_score: number;
  severity_breakdown: SeverityBreakdown;
  dominant_rule_id?: string | null;
}

export interface PatternSummary {
  repeated_rules: string[];
  affected_protocols: string[];
  affected_sessions_count: number;
}

export interface InvestigationIntelligenceResponse {
  investigation_id: string;
  generated_at: string;
  risk_summary: RiskSummaryIntelligence;
  protocol_exposure: ProtocolExposureItem[];
  pattern_summary: PatternSummary;
  insights: IntelligenceInsight[];
}

export interface AnomalyResultItem {
  id: string;
  investigation_id: string;
  session_id: string;
  tcp_stream: number;
  protocol: string;
  src: string;
  dst: string;
  src_port: number;
  dst_port: number;
  model_version: string;
  feature_version: string;
  anomaly_score: number;
  anomaly_label: "ANOMALY" | "ELEVATED" | "NORMAL" | string;
  is_anomalous: boolean;
  confidence_band: "HIGH" | "MEDIUM" | "LOW" | string;
  evidence_state: "OBSERVED" | "INCOMPLETE" | "UNKNOWN" | string;
  contributing_features: string[];
  supporting_finding_ids: string[];
  supporting_event_ids: string[];
  supporting_frame_numbers: number[];
  explanation: string;
  created_at?: string | null;
}

export interface AnomalySummary {
  total_sessions_analyzed: number;
  anomalous_sessions_count: number;
  elevated_sessions_count: number;
  normal_sessions_count: number;
  highest_anomaly_score: number;
  model_version: string;
  feature_version: string;
}

export interface InvestigationAnomaliesResponse {
  investigation_id: string;
  generated_at: string;
  model_version: string;
  feature_version: string;
  training_context: string;
  summary: AnomalySummary;
  results: AnomalyResultItem[];
}
