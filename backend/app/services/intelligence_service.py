import json
import datetime
from typing import List, Dict, Set, Optional
from sqlalchemy import func, distinct
from sqlalchemy.orm import Session as DbSession

from backend.app.models.database import Investigation, Capture, Session as DbSessionModel, Finding, SecurityEvent
from backend.app.schemas.investigation import SeverityBreakdown
from backend.app.schemas.intelligence import (
    InvestigationIntelligenceResponse,
    RiskSummaryIntelligence,
    ProtocolExposureItem,
    PatternSummary,
    IntelligenceInsight,
)

# Rule mapping metadata for deterministic insight generation
RULE_INSIGHT_MAP = {
    "EMAIL-PLAINTEXT-NOT-OFFERED-001": {
        "id": "INTEL-REPEATED-PLAINTEXT-001",
        "title": "Repeated Plaintext Email Traffic Exposure",
        "desc_template": "Plaintext email protocol transmission was observed across {count} distinct sessions without STARTTLS/STLS encryption capabilities.",
        "default_severity": "CRITICAL",
        "default_confidence": "HIGH",
    },
    "EMAIL-STARTTLS-OFFERED-NOT-USED-001": {
        "id": "INTEL-REPEATED-STARTTLS-BYPASS-001",
        "title": "Repeated STARTTLS Encryption Bypass Observed",
        "desc_template": "STARTTLS upgrade capabilities were advertised by servers but unencrypted traffic was transmitted across {count} distinct sessions.",
        "default_severity": "CRITICAL",
        "default_confidence": "HIGH",
    },
    "TLS-WEAK-STATIC-RSA-001": {
        "id": "INTEL-REPEATED-WEAK-CRYPTO-001",
        "title": "Repeated Legacy Static RSA Key Exchange Observed",
        "desc_template": "Weak static RSA cipher suites lacking Perfect Forward Secrecy (PFS) were negotiated across {count} distinct sessions.",
        "default_severity": "HIGH",
        "default_confidence": "HIGH",
    },
    "TLS-ALERT-CERT-OBSERVED-001": {
        "id": "INTEL-REPEATED-CERT-FAILURE-001",
        "title": "Repeated TLS Certificate Validation Alerts Observed",
        "desc_template": "Explicit TLS certificate alerts (bad certificate, expired, or untrusted) were observed on the wire across {count} distinct sessions.",
        "default_severity": "HIGH",
        "default_confidence": "HIGH",
    },
    "TLS-HANDSHAKE-FAILED-001": {
        "id": "INTEL-REPEATED-TLS-FAILURE-001",
        "title": "Repeated TLS Handshake Session Failures Observed",
        "desc_template": "TLS handshake negotiations failed or terminated abruptly across {count} distinct sessions.",
        "default_severity": "MEDIUM",
        "default_confidence": "HIGH",
    },
}


def build_empty_intelligence_response(investigation_id: str) -> InvestigationIntelligenceResponse:
    """Helper to return clean zeroed intelligence payload for empty investigations."""
    empty_severity = SeverityBreakdown(critical=0, high=0, medium=0, low=0, info=0)
    protocol_items = [
        ProtocolExposureItem(
            protocol=proto,
            total_sessions=0,
            affected_sessions=0,
            active_findings_count=0,
            highest_risk_score=0,
            severity_breakdown=empty_severity,
            dominant_rule_id=None,
        )
        for proto in ["SMTP", "IMAP", "POP3"]
    ]

    return InvestigationIntelligenceResponse(
        investigation_id=investigation_id,
        generated_at=datetime.datetime.now(datetime.timezone.utc),
        risk_summary=RiskSummaryIntelligence(
            highest_risk_score=0,
            highest_risk_finding_id=None,
            highest_risk_session_id=None,
            active_findings_count=0,
            affected_sessions_count=0,
            risk_concentration={},
        ),
        protocol_exposure=protocol_items,
        pattern_summary=PatternSummary(
            repeated_rules=[],
            affected_protocols=[],
            affected_sessions_count=0,
        ),
        insights=[],
    )


def compute_investigation_intelligence(investigation_id: str, db: DbSession) -> InvestigationIntelligenceResponse:
    """
    Computes authoritative, explainable security intelligence and correlation patterns
    strictly from persisted database records (Investigation, Capture, Session, SecurityEvent, Finding).
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return None

    # Fetch captures for this investigation
    captures = db.query(Capture).filter(Capture.investigation_id == investigation_id).all()
    if not captures:
        return build_empty_intelligence_response(investigation_id)

    capture_ids = [c.id for c in captures]

    # Fetch all sessions under these captures
    sessions = db.query(DbSessionModel).filter(DbSessionModel.capture_id.in_(capture_ids)).all()
    if not sessions:
        return build_empty_intelligence_response(investigation_id)

    session_map = {s.id: s for s in sessions}
    session_ids = list(session_map.keys())

    # Fetch all ACTIVE findings under these sessions
    active_findings = (
        db.query(Finding)
        .filter(Finding.session_id.in_(session_ids), Finding.status == "ACTIVE")
        .order_by(Finding.risk_score.desc(), Finding.id.asc())
        .all()
    )

    if not active_findings:
        # If there are sessions but no active findings, compute session protocol counts
        empty_severity = SeverityBreakdown(critical=0, high=0, medium=0, low=0, info=0)
        proto_session_counts: Dict[str, int] = {}
        for s in sessions:
            proto_session_counts[s.protocol] = proto_session_counts.get(s.protocol, 0) + 1

        protocol_items = [
            ProtocolExposureItem(
                protocol=proto,
                total_sessions=proto_session_counts.get(proto, 0),
                affected_sessions=0,
                active_findings_count=0,
                highest_risk_score=0,
                severity_breakdown=empty_severity,
                dominant_rule_id=None,
            )
            for proto in ["SMTP", "IMAP", "POP3"]
        ]

        return InvestigationIntelligenceResponse(
            investigation_id=investigation_id,
            generated_at=datetime.datetime.now(datetime.timezone.utc),
            risk_summary=RiskSummaryIntelligence(
                highest_risk_score=0,
                highest_risk_finding_id=None,
                highest_risk_session_id=None,
                active_findings_count=0,
                affected_sessions_count=0,
                risk_concentration={},
            ),
            protocol_exposure=protocol_items,
            pattern_summary=PatternSummary(
                repeated_rules=[],
                affected_protocols=[],
                affected_sessions_count=0,
            ),
            insights=[],
        )

    # 1. Risk Summary Computation
    highest_finding = active_findings[0]  # Already sorted by risk_score DESC
    highest_risk_score = highest_finding.risk_score
    highest_risk_finding_id = highest_finding.id
    highest_risk_session_id = highest_finding.session_id

    active_findings_count = len(active_findings)

    actionable_sessions: Set[str] = {
        f.session_id for f in active_findings if f.severity != "INFO"
    }
    affected_sessions_count = len(actionable_sessions)

    risk_concentration: Dict[str, int] = {}
    for f in active_findings:
        risk_concentration[f.rule_id] = risk_concentration.get(f.rule_id, 0) + 1

    # 2. Protocol Exposure Computation
    proto_total_sessions: Dict[str, int] = {}
    for s in sessions:
        proto_total_sessions[s.protocol] = proto_total_sessions.get(s.protocol, 0) + 1

    proto_findings: Dict[str, List[Finding]] = {}
    for f in active_findings:
        proto_findings.setdefault(f.protocol, []).append(f)

    protocol_items: List[ProtocolExposureItem] = []
    for proto in ["SMTP", "IMAP", "POP3"]:
        p_findings = proto_findings.get(proto, [])
        p_affected_sessions = len({f.session_id for f in p_findings if f.severity != "INFO"})
        p_highest_risk = max([f.risk_score for f in p_findings], default=0)

        p_sev_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        p_rule_counts: Dict[str, int] = {}

        for f in p_findings:
            p_sev_map[f.severity] = p_sev_map.get(f.severity, 0) + 1
            p_rule_counts[f.rule_id] = p_rule_counts.get(f.rule_id, 0) + 1

        dominant_rule = None
        if p_rule_counts:
            # Sort by count DESC, then rule_id ASC for determinism
            sorted_rules = sorted(p_rule_counts.items(), key=lambda x: (-x[1], x[0]))
            dominant_rule = sorted_rules[0][0]

        protocol_items.append(
            ProtocolExposureItem(
                protocol=proto,
                total_sessions=proto_total_sessions.get(proto, 0),
                affected_sessions=p_affected_sessions,
                active_findings_count=len(p_findings),
                highest_risk_score=p_highest_risk,
                severity_breakdown=SeverityBreakdown(
                    critical=p_sev_map["CRITICAL"],
                    high=p_sev_map["HIGH"],
                    medium=p_sev_map["MEDIUM"],
                    low=p_sev_map["LOW"],
                    info=p_sev_map["INFO"],
                ),
                dominant_rule_id=dominant_rule,
            )
        )

    # 3. Rule Grouping for Repeated Pattern Correlation
    rule_findings_map: Dict[str, List[Finding]] = {}
    for f in active_findings:
        rule_findings_map.setdefault(f.rule_id, []).append(f)

    repeated_rules: List[str] = []
    repeated_protocols_set: Set[str] = set()
    repeated_sessions_set: Set[str] = set()

    insights: List[IntelligenceInsight] = []

    # Process each rule for repeated correlation insight generation
    for rule_id, f_list in rule_findings_map.items():
        distinct_sessions = {f.session_id for f in f_list}
        distinct_count = len(distinct_sessions)

        # Insight condition: Must affect MORE THAN 1 distinct session
        if distinct_count > 1 and rule_id in RULE_INSIGHT_MAP:
            meta = RULE_INSIGHT_MAP[rule_id]
            repeated_rules.append(rule_id)
            repeated_sessions_set.update(distinct_sessions)
            for f in f_list:
                repeated_protocols_set.add(f.protocol)

            supporting_finding_ids = sorted([f.id for f in f_list])
            supporting_session_ids = sorted(list(distinct_sessions))

            # Aggregate evidence event IDs and frame numbers from supporting findings
            ev_event_ids_set: Set[str] = set()
            ev_frame_nums_set: Set[int] = set()
            incomplete_evidence = False

            remediation_text = None
            for f in f_list:
                # Deserialize evidence_event_ids
                if f.evidence_event_ids:
                    try:
                        e_ids = json.loads(f.evidence_event_ids) if isinstance(f.evidence_event_ids, str) else f.evidence_event_ids
                        if isinstance(e_ids, list):
                            ev_event_ids_set.update(e_ids)
                    except Exception:
                        pass

                # Deserialize evidence_frame_numbers
                if f.evidence_frame_numbers:
                    try:
                        f_nums = json.loads(f.evidence_frame_numbers) if isinstance(f.evidence_frame_numbers, str) else f.evidence_frame_numbers
                        if isinstance(f_nums, list):
                            ev_frame_nums_set.update(f_nums)
                    except Exception:
                        pass

                # Deserialize details_json
                if f.details_json:
                    try:
                        det = json.loads(f.details_json) if isinstance(f.details_json, str) else f.details_json
                        if not remediation_text and isinstance(det, dict) and isinstance(det.get("remediation"), str):
                            remediation_text = det.get("remediation")
                    except Exception:
                        pass

                # Check evidence quality
                sess_obj = session_map.get(f.session_id)
                if sess_obj and sess_obj.completeness != "COMPLETE":
                    incomplete_evidence = True

            evidence_state = "INCOMPLETE" if incomplete_evidence else "OBSERVED"
            max_risk = max([f.risk_score for f in f_list])

            insights.append(
                IntelligenceInsight(
                    id=meta["id"],
                    title=meta["title"],
                    description=meta["desc_template"].format(count=distinct_count),
                    severity=meta["default_severity"],
                    confidence=meta["default_confidence"],
                    risk_score=max_risk,
                    evidence_state=evidence_state,
                    supporting_finding_ids=supporting_finding_ids,
                    supporting_session_ids=supporting_session_ids,
                    supporting_event_ids=sorted(list(ev_event_ids_set)),
                    supporting_frame_numbers=sorted(list(ev_frame_nums_set)),
                    remediation=remediation_text,
                )
            )

    # Sort insights deterministically by risk_score DESC, then id ASC
    insights.sort(key=lambda x: (-x.risk_score, x.id))
    repeated_rules.sort()
    sorted_affected_protocols = sorted(list(repeated_protocols_set))

    return InvestigationIntelligenceResponse(
        investigation_id=investigation_id,
        generated_at=datetime.datetime.now(datetime.timezone.utc),
        risk_summary=RiskSummaryIntelligence(
            highest_risk_score=highest_risk_score,
            highest_risk_finding_id=highest_risk_finding_id,
            highest_risk_session_id=highest_risk_session_id,
            active_findings_count=active_findings_count,
            affected_sessions_count=affected_sessions_count,
            risk_concentration=risk_concentration,
        ),
        protocol_exposure=protocol_items,
        pattern_summary=PatternSummary(
            repeated_rules=repeated_rules,
            affected_protocols=sorted_affected_protocols,
            affected_sessions_count=len(repeated_sessions_set),
        ),
        insights=insights,
    )
