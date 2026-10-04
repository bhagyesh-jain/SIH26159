import json
import datetime
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session as DBSession

from backend.app.models.database import Session as SessionModel, SecurityEvent, Finding


FEATURE_NAMES = [
    "session_duration_sec",
    "is_protocol_smtp",
    "is_protocol_imap",
    "is_protocol_pop3",
    "is_non_standard_dst_port",
    "event_count",
    "finding_count",
    "highest_risk_score",
    "starttls_advertised",
    "starttls_requested",
    "starttls_accepted",
    "starttls_negotiated",
    "starttls_bypassed",
    "tls_12_observed",
    "tls_13_observed",
    "weak_rsa_observed",
    "tls_alert_count",
    "cert_alert_count",
    "handshake_failed",
]

FEATURE_DESCRIPTIONS = {
    "session_duration_sec": "session duration in seconds",
    "is_protocol_smtp": "SMTP protocol connection",
    "is_protocol_imap": "IMAP protocol connection",
    "is_protocol_pop3": "POP3 protocol connection",
    "is_non_standard_dst_port": "non-standard destination port usage",
    "event_count": "total security event volume",
    "finding_count": "active finding volume",
    "highest_risk_score": "maximum risk score",
    "starttls_advertised": "STARTTLS advertisement capability",
    "starttls_requested": "STARTTLS upgrade request",
    "starttls_accepted": "STARTTLS server acceptance",
    "starttls_negotiated": "STARTTLS encrypted channel establishment",
    "starttls_bypassed": "STARTTLS advertised but unutilized (cleartext transition)",
    "tls_12_observed": "TLS 1.2 protocol negotiation",
    "tls_13_observed": "TLS 1.3 protocol negotiation",
    "weak_rsa_observed": "weak static RSA cipher suite selection",
    "tls_alert_count": "TLS alert record frequency",
    "cert_alert_count": "certificate validation alert frequency",
    "handshake_failed": "TLS handshake failure frequency",
}


STANDARD_MAIL_PORTS = {25, 465, 587, 143, 993, 110, 995}


class SessionFeatureVector:
    def __init__(
        self,
        session_id: str,
        investigation_id: str,
        tcp_stream: int,
        protocol: str,
        src: str,
        dst: str,
        src_port: int,
        dst_port: int,
        features: Dict[str, float],
        evidence_state: str,
        supporting_finding_ids: List[str],
        supporting_event_ids: List[str],
        supporting_frame_numbers: List[int],
    ):
        self.session_id = session_id
        self.investigation_id = investigation_id
        self.tcp_stream = tcp_stream
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.src_port = src_port
        self.dst_port = dst_port
        self.features = features
        self.evidence_state = evidence_state
        self.supporting_finding_ids = supporting_finding_ids
        self.supporting_event_ids = supporting_event_ids
        self.supporting_frame_numbers = supporting_frame_numbers

    def to_numeric_array(self) -> List[float]:
        return [self.features.get(name, 0.0) for name in FEATURE_NAMES]


def extract_session_features(
    session: SessionModel,
    security_events: List[SecurityEvent],
    findings: List[Finding],
    investigation_id: str,
) -> SessionFeatureVector:
    """
    Extracts a deterministic ML feature vector from persisted structured evidence.
    CRITICAL SECURITY & FORENSIC BOUNDARIES:
    - Does NOT read PCAP files or invoke TShark.
    - Does NOT use PCAP filename, scenario identifier, or capture filename as features.
    - Uses One-Hot encoding for protocols to eliminate ordinal bias.
    - Uses non-standard port indicator to prevent ephemeral client source port noise.
    - Preserves evidence provenance (finding IDs, event IDs, frame numbers).
    """
    # 1. Session duration
    duration = 0.0
    if session.started_at and session.ended_at:
        try:
            duration = max(0.0, (session.ended_at - session.started_at).total_seconds())
        except Exception:
            duration = 0.0

    # 2. One-hot protocol encoding
    proto_upper = (session.protocol or "").upper()
    is_protocol_smtp = 1.0 if proto_upper == "SMTP" else 0.0
    is_protocol_imap = 1.0 if proto_upper == "IMAP" else 0.0
    is_protocol_pop3 = 1.0 if proto_upper == "POP3" else 0.0

    # 3. Non-standard destination port usage
    dst_port = session.dst_port or 0
    is_non_standard_dst_port = 1.0 if dst_port not in STANDARD_MAIL_PORTS else 0.0

    # 4. Security events count
    event_count = float(len(security_events))

    # 5 & 6. Findings metrics
    active_findings = [f for f in findings if f.status == "ACTIVE"]
    finding_count = float(len(active_findings))
    highest_risk = float(max([f.risk_score for f in active_findings], default=0))

    # STARTTLS features
    starttls_advertised = 0.0
    starttls_requested = 0.0
    starttls_accepted = 0.0
    starttls_negotiated = 0.0
    starttls_bypassed = 0.0

    # TLS features
    tls_12_observed = 0.0
    tls_13_observed = 0.0
    weak_rsa_observed = 0.0
    tls_alert_count = 0.0
    cert_alert_count = 0.0
    handshake_failed = 0.0

    # Evidence references
    supporting_finding_ids: List[str] = [f.id for f in active_findings]
    supporting_event_ids: List[str] = [e.id for e in security_events]
    frame_numbers_set = set()

    evidence_incomplete = session.completeness == "INCOMPLETE"

    for sevt in security_events:
        if sevt.completeness_status in ("TRUNCATED", "INCOMPLETE"):
            evidence_incomplete = True

        # Parse frame numbers
        if sevt.frame_numbers:
            for f_str in sevt.frame_numbers.split(","):
                f_str = f_str.strip()
                if f_str.isdigit():
                    frame_numbers_set.add(int(f_str))

        # Check upgrade status
        up_status = (sevt.upgrade_status or "").upper()
        if up_status in ("OFFERED", "ADVERTISED", "ACCEPTED", "NEGOTIATED"):
            starttls_advertised = 1.0
        if up_status == "REQUESTED":
            starttls_requested = 1.0
        if up_status == "ACCEPTED":
            starttls_accepted = 1.0
        if up_status == "NEGOTIATED":
            starttls_negotiated = 1.0
        if up_status == "OFFERED_NOT_USED":
            starttls_bypassed = 1.0

        # Check details_json for TLS features
        if sevt.details_json:
            try:
                dt = json.loads(sevt.details_json)
                version = (dt.get("tls_version") or dt.get("version") or "").upper()
                cipher = (dt.get("cipher_suite") or dt.get("cipher") or "").upper()
                key_exchange = (dt.get("key_exchange") or "").upper()

                if "1.2" in version:
                    tls_12_observed = 1.0
                if "1.3" in version:
                    tls_13_observed = 1.0
                if "STATIC_RSA" in key_exchange or ("RSA" in cipher and "ECDHE" not in cipher):
                    weak_rsa_observed = 1.0
            except Exception:
                pass

        evt_type = (sevt.event_type or "").upper()
        if "ALERT" in evt_type or "TLS_ALERT" in evt_type:
            tls_alert_count += 1.0
            if "CERT" in evt_type or "CERTIFICATE" in (sevt.observed_value or "").upper():
                cert_alert_count += 1.0
        if "FAILED" in evt_type or "HANDSHAKE_FAILED" in evt_type or "HANDSHAKE_FAILURE" in (sevt.observed_value or "").upper():
            handshake_failed = 1.0

    # Also inspect findings for weak RSA or bypass flags
    for f in active_findings:
        if f.rule_id == "EMAIL-STARTTLS-OFFERED-NOT-USED-001":
            starttls_bypassed = 1.0
        elif f.rule_id == "TLS-WEAK-STATIC-RSA-001":
            weak_rsa_observed = 1.0
        elif f.rule_id == "TLS-HANDSHAKE-FAILED-001":
            handshake_failed = 1.0
        elif f.rule_id == "TLS-ALERT-CERT-OBSERVED-001":
            cert_alert_count += 1.0

        # Collect frame numbers from finding details
        if f.evidence_frame_numbers:
            try:
                fn_list = json.loads(f.evidence_frame_numbers)
                for fn in fn_list:
                    if isinstance(fn, int):
                        frame_numbers_set.add(fn)
            except Exception:
                pass

    evidence_state = "INCOMPLETE" if evidence_incomplete else "OBSERVED"

    features = {
        "session_duration_sec": duration,
        "is_protocol_smtp": is_protocol_smtp,
        "is_protocol_imap": is_protocol_imap,
        "is_protocol_pop3": is_protocol_pop3,
        "is_non_standard_dst_port": is_non_standard_dst_port,
        "event_count": event_count,
        "finding_count": finding_count,
        "highest_risk_score": highest_risk,
        "starttls_advertised": starttls_advertised,
        "starttls_requested": starttls_requested,
        "starttls_accepted": starttls_accepted,
        "starttls_negotiated": starttls_negotiated,
        "starttls_bypassed": starttls_bypassed,
        "tls_12_observed": tls_12_observed,
        "tls_13_observed": tls_13_observed,
        "weak_rsa_observed": weak_rsa_observed,
        "tls_alert_count": tls_alert_count,
        "cert_alert_count": cert_alert_count,
        "handshake_failed": handshake_failed,
    }

    return SessionFeatureVector(
        session_id=session.id,
        investigation_id=investigation_id,
        tcp_stream=session.tcp_stream,
        protocol=session.protocol or "UNKNOWN",
        src=session.src,
        dst=session.dst,
        src_port=session.src_port,
        dst_port=session.dst_port,
        features=features,
        evidence_state=evidence_state,
        supporting_finding_ids=supporting_finding_ids,
        supporting_event_ids=supporting_event_ids,
        supporting_frame_numbers=sorted(list(frame_numbers_set)),
    )
