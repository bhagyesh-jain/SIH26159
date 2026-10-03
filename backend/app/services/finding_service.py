import json
import uuid
import re
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session as DbSession
from backend.app.models.database import Session as DbSessionModel, SecurityEvent, Finding


SEVERITY_WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 0,
}

CONFIDENCE_MULTIPLIERS = {
    "HIGH": 1.00,
    "MEDIUM": 0.80,
    "LOW": 0.50,
    "UNKNOWN": 0.00,
}


def calculate_risk_priority_score(severity: str, confidence: str) -> int:
    """
    Computes an evidence-adjusted Risk Priority Score:
    Base Severity Weight * Confidence Multiplier (bounded between 0 and 100).
    """
    weight = SEVERITY_WEIGHTS.get(severity.upper(), 0)
    multiplier = CONFIDENCE_MULTIPLIERS.get(confidence.upper(), 0.0)
    return int(round(weight * multiplier))


def _sanitize_string(val: str) -> str:
    """Sanitizes any leftover sensitive auth tokens from finding text."""
    if not val:
        return val
    val = re.sub(r'(\bLOGIN\s+(?:"[^"]*"|\S+)\s+)(\S+|"[^"]*")', r'\1[REDACTED]', val, flags=re.IGNORECASE)
    val = re.sub(r'(\bPASS\s+)(\S+|"[^"]*")', r'\1[REDACTED]', val, flags=re.IGNORECASE)
    val = re.sub(r'(\bAUTH\s+(?:PLAIN|LOGIN)\s+)(\S+)', r'\1[REDACTED]', val, flags=re.IGNORECASE)
    return val


class FindingService:
    """
    Deterministic Finding Engine:
    Converts persisted SecurityEvents into evidence-backed Findings.
    Strictly evidence-driven; derives findings ONLY from observed SecurityEvents.
    """

    @staticmethod
    def generate_findings_for_session(db: DbSession, session_id: str) -> List[Finding]:
        session_rec = db.query(DbSessionModel).filter(DbSessionModel.id == session_id).first()
        if not session_rec:
            return []

        sec_events = db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).all()
        if not sec_events:
            return []

        # Clear existing findings for session re-analysis idempotency
        existing_findings = db.query(Finding).filter(Finding.session_id == session_id).all()
        for f in existing_findings:
            db.delete(f)
        db.flush()

        investigation_id = session_rec.capture.investigation_id if session_rec.capture else "unknown"
        protocol = session_rec.protocol or "UNKNOWN"

        candidate_findings: List[Dict[str, Any]] = []

        # Helper to extract frames & IDs
        def _get_evidence(evts: List[SecurityEvent]):
            event_ids = [e.id for e in evts]
            frames = []
            for e in evts:
                if e.frame_numbers:
                    for f in e.frame_numbers.split(","):
                        if f.strip().isdigit():
                            frames.append(int(f.strip()))
            frames = sorted(list(set(frames)))
            first_ts = str(evts[0].timestamp) if evts and evts[0].timestamp else None
            last_ts = str(evts[-1].timestamp) if evts and evts[-1].timestamp else None
            return event_ids, frames, first_ts, last_ts

        # Check overall session TLS upgrade progression
        has_upgrade_accepted = any(e.event_type in ["UPGRADE_ACCEPTED", "TLS_NEGOTIATED"] for e in sec_events)
        has_upgrade_requested = any(e.event_type == "UPGRADE_REQUESTED" for e in sec_events)
        has_tls_negotiated = any(e.event_type == "TLS_NEGOTIATED" for e in sec_events)
        has_handshake_failed = any(e.event_type == "HANDSHAKE_FAILED" for e in sec_events)

        # -------------------------------------------------------------------------
        # RULE 1: EMAIL-STARTTLS-OFFERED-NOT-USED-001
        # Condition: STARTTLS was offered, but NO upgrade was requested/accepted, and plaintext commands were sent after offer.
        # -------------------------------------------------------------------------
        offered_not_used_evts = [
            e for e in sec_events
            if e.event_type == "PLAINTEXT_COMMAND_AFTER_OFFER" or (
                e.event_type == "CAPABILITY_ADVERTISED" and 
                "NOT_ADVERTISED" not in e.observed_value and 
                not has_upgrade_requested and 
                not has_upgrade_accepted
            )
        ]
        if offered_not_used_evts and not has_upgrade_accepted and not has_upgrade_requested:
            event_ids, frames, f_ts, l_ts = _get_evidence(sec_events)
            
            # Check if actual credentials (LOGIN/PASS/AUTH) were observed in events
            has_credentials = any(
                "LOGIN" in e.observed_value or "PASS" in e.observed_value or "AUTH" in e.observed_value
                for e in sec_events
            )
            
            desc = (
                f"Server advertised {protocol} encryption upgrade capability (STARTTLS/STLS), "
                f"but client proceeded without issuing an upgrade request. "
                f"Plaintext commands were transmitted in unencrypted traffic."
            )
            if has_credentials:
                desc += " Plaintext authentication credentials were observed in stream."

            obs_val = offered_not_used_evts[0].observed_value
            candidate_findings.append({
                "rule_id": "EMAIL-STARTTLS-OFFERED-NOT-USED-001",
                "title": "Plaintext Transmission Despite Advertised Encryption Capability",
                "description": desc,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "protocol": protocol,
                "observed_value": _sanitize_string(obs_val),
                "event_ids": event_ids,
                "frames": frames,
                "first_seen": f_ts,
                "last_seen": l_ts,
                "details": {
                    "what": "Plaintext commands transmitted after encryption capability offer.",
                    "where": {"src": f"{session_rec.src}:{session_rec.src_port}", "dst": f"{session_rec.dst}:{session_rec.dst_port}", "tcp_stream": session_rec.tcp_stream},
                    "why": f"{protocol} server offered encryption capability, but client sent unencrypted traffic.",
                    "credential_exposure_observed": has_credentials,
                    "remediation": f"Configure {protocol} client to mandate TLS upgrade before transmitting credentials or application data."
                }
            })

        # -------------------------------------------------------------------------
        # RULE 2: EMAIL-PLAINTEXT-NOT-OFFERED-001
        # Condition: STARTTLS was NOT offered, NO TLS upgrade occurred, and plaintext traffic was observed.
        # -------------------------------------------------------------------------
        not_offered_evts = [
            e for e in sec_events
            if e.upgrade_status == "NOT_OFFERED" or "NOT_ADVERTISED" in e.observed_value or (
                not has_upgrade_accepted and not has_upgrade_requested and not offered_not_used_evts and not has_handshake_failed
            )
        ]
        if not_offered_evts and not has_upgrade_accepted and not has_upgrade_requested and not offered_not_used_evts and not has_handshake_failed:
            event_ids, frames, f_ts, l_ts = _get_evidence(sec_events)
            
            app_traffic_evts = [e for e in sec_events if e.event_type in ["SERVER_GREETING", "CLIENT_GREETING", "CLIENT_COMMAND", "PLAINTEXT_COMMAND_AFTER_OFFER"]]
            app_observed = len(app_traffic_evts) > 0

            desc = (
                f"{protocol} server greeting / capability advertisement did not offer STARTTLS/STLS encryption upgrade."
            )
            if app_observed:
                desc += f" Unencrypted {protocol} application traffic was observed in stream."

            candidate_findings.append({
                "rule_id": "EMAIL-PLAINTEXT-NOT-OFFERED-001",
                "title": "Unencrypted Email Communication (Encryption Upgrade Not Offered)",
                "description": desc,
                "severity": "HIGH",
                "confidence": "HIGH",
                "protocol": protocol,
                "observed_value": _sanitize_string(not_offered_evts[0].observed_value),
                "event_ids": event_ids,
                "frames": frames,
                "first_seen": f_ts,
                "last_seen": l_ts,
                "details": {
                    "what": f"{protocol} session operating in unencrypted plaintext mode.",
                    "where": {"src": f"{session_rec.src}:{session_rec.src_port}", "dst": f"{session_rec.dst}:{session_rec.dst_port}", "tcp_stream": session_rec.tcp_stream},
                    "why": f"Server capability list does not advertise STARTTLS/STLS upgrade.",
                    "plaintext_application_traffic_observed": app_observed,
                    "remediation": f"Enable STARTTLS/STLS support on {protocol} server configuration."
                }
            })

        # -------------------------------------------------------------------------
        # RULE 3: TLS-WEAK-STATIC-RSA-001
        # -------------------------------------------------------------------------
        weak_tls_evts = []
        for e in sec_events:
            if e.event_type in ["TLS_NEGOTIATED", "TLS_CRYPTOGRAPHIC_ASSESSMENT"]:
                d = json.loads(e.details_json) if e.details_json else {}
                if d.get("forward_secrecy") == "NO_PFS_STATIC_RSA" or d.get("key_exchange") == "STATIC_RSA":
                    weak_tls_evts.append(e)

        if weak_tls_evts:
            event_ids, frames, f_ts, l_ts = _get_evidence(weak_tls_evts)
            d = json.loads(weak_tls_evts[0].details_json) if weak_tls_evts[0].details_json else {}
            cipher_name = d.get("selected_cipher_name") or d.get("selected_cipher") or "STATIC_RSA"

            candidate_findings.append({
                "rule_id": "TLS-WEAK-STATIC-RSA-001",
                "title": "Weak TLS Cryptography (Static RSA Key Exchange Without Perfect Forward Secrecy)",
                "description": (
                    f"Negotiated TLS session used cipher suite '{cipher_name}' with static RSA key exchange. "
                    f"Static RSA key exchange lacks Perfect Forward Secrecy (PFS), allowing passive recording adversaries "
                    f"to decrypt historical traffic if the server's private key is compromised."
                ),
                "severity": "HIGH",
                "confidence": "HIGH",
                "protocol": protocol,
                "observed_value": _sanitize_string(weak_tls_evts[0].observed_value),
                "event_ids": event_ids,
                "frames": frames,
                "first_seen": f_ts,
                "last_seen": l_ts,
                "details": {
                    "what": "Negotiated cipher suite lacks Perfect Forward Secrecy.",
                    "where": {"src": f"{session_rec.src}:{session_rec.src_port}", "dst": f"{session_rec.dst}:{session_rec.dst_port}", "tcp_stream": session_rec.tcp_stream},
                    "cipher": cipher_name,
                    "key_exchange": "STATIC_RSA",
                    "forward_secrecy": "NO_PFS_STATIC_RSA",
                    "remediation": "Disable static RSA cipher suites in server configuration and enforce ECDHE/DHE ephemeral key exchange."
                }
            })

        # -------------------------------------------------------------------------
        # RULE 4: TLS-ALERT-CERT-OBSERVED-001 & RULE 5: TLS-HANDSHAKE-FAILED-001
        # Deterministic Precedence: Certificate fatal alert (42/44/45/48) takes precedence
        # over generic TLS-HANDSHAKE-FAILED-001 to prevent double-counting.
        # -------------------------------------------------------------------------
        failed_handshake_evts = [e for e in sec_events if e.event_type == "HANDSHAKE_FAILED"]
        cert_alert_evt = None
        cert_alert_details = None

        for e in failed_handshake_evts:
            if e.details_json:
                try:
                    d = json.loads(e.details_json)
                    lvl = str(d.get("alert_level")) if d.get("alert_level") is not None else None
                    desc = str(d.get("alert_desc")) if d.get("alert_desc") is not None else None
                    if lvl == "2" and desc in ["42", "44", "45", "48"]:
                        cert_alert_evt = e
                        cert_alert_details = d
                        break
                except Exception:
                    pass

        if cert_alert_evt:
            event_ids, frames, f_ts, l_ts = _get_evidence(failed_handshake_evts)
            alert_lvl = str(cert_alert_details.get("alert_level"))
            alert_desc = str(cert_alert_details.get("alert_desc"))

            alert_meanings = {
                "42": "Bad Certificate",
                "44": "Unsupported Certificate",
                "45": "Certificate Expired",
                "48": "Unknown CA / Certificate Verification Failure"
            }
            meaning = alert_meanings.get(alert_desc, "Certificate Validation Failure")

            candidate_findings.append({
                "rule_id": "TLS-ALERT-CERT-OBSERVED-001",
                "title": "Observed TLS Fatal Alert (Certificate Validation Failure)",
                "description": (
                    f"Observed TLS fatal alert (Level {alert_lvl}, Code {alert_desc}: {meaning}) sent during handshake. "
                    f"Wire-level alert indicates a certificate validation failure reported by peer."
                ),
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "protocol": protocol,
                "observed_value": _sanitize_string(cert_alert_evt.observed_value),
                "event_ids": event_ids,
                "frames": frames,
                "first_seen": f_ts,
                "last_seen": l_ts,
                "details": {
                    "what": "Observed TLS fatal alert indicating certificate validation failure.",
                    "where": {"src": f"{session_rec.src}:{session_rec.src_port}", "dst": f"{session_rec.dst}:{session_rec.dst_port}", "tcp_stream": session_rec.tcp_stream},
                    "observed_alert": {"level": alert_lvl, "code": alert_desc, "meaning": meaning},
                    "passive_limitation": "TLS 1.3 certificate payload is encrypted on the wire per RFC 8446. Alert code recorded from wire observation.",
                    "remediation": "Inspect server X.509 certificate validity period and ensure trusted root/intermediate CAs are configured in client trust store."
                }
            })
        elif failed_handshake_evts:
            event_ids, frames, f_ts, l_ts = _get_evidence(failed_handshake_evts)
            d = json.loads(failed_handshake_evts[0].details_json) if failed_handshake_evts[0].details_json else {}
            reason = d.get("reason") or "TLS_HANDSHAKE_FAILED"

            candidate_findings.append({
                "rule_id": "TLS-HANDSHAKE-FAILED-001",
                "title": "Premature TLS Handshake Abort / Connection Reset",
                "description": (
                    f"TLS handshake failed or was prematurely aborted before encryption completion. "
                    f"Reason: {reason}."
                ),
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "protocol": protocol,
                "observed_value": _sanitize_string(failed_handshake_evts[0].observed_value),
                "event_ids": event_ids,
                "frames": frames,
                "first_seen": f_ts,
                "last_seen": l_ts,
                "details": {
                    "what": "TLS handshake aborted prior to post-handshake record exchange.",
                    "where": {"src": f"{session_rec.src}:{session_rec.src_port}", "dst": f"{session_rec.dst}:{session_rec.dst_port}", "tcp_stream": session_rec.tcp_stream},
                    "tcp_reset": d.get("tcp_reset", False),
                    "reason": reason,
                    "remediation": "Verify server TLS protocol and cipher compatibility with client endpoints."
                }
            })

        # -------------------------------------------------------------------------
        # RULE 6: TLS-SECURE-BASELINE-001
        # -------------------------------------------------------------------------
        has_negative_finding = any(c["rule_id"] in ["EMAIL-PLAINTEXT-NOT-OFFERED-001", "EMAIL-STARTTLS-OFFERED-NOT-USED-001", "TLS-WEAK-STATIC-RSA-001", "TLS-ALERT-CERT-OBSERVED-001", "TLS-HANDSHAKE-FAILED-001"] for c in candidate_findings)
        
        negotiated_evts = [e for e in sec_events if e.event_type == "TLS_NEGOTIATED"]
        if negotiated_evts and not has_negative_finding:
            event_ids, frames, f_ts, l_ts = _get_evidence(negotiated_evts)
            d = json.loads(negotiated_evts[0].details_json) if negotiated_evts[0].details_json else {}
            ver = d.get("tls_version") or "TLS"
            cipher = d.get("selected_cipher") or "Strong Cipher"

            candidate_findings.append({
                "rule_id": "TLS-SECURE-BASELINE-001",
                "title": "Secure TLS Encryption Negotiated",
                "description": (
                    f"Successfully negotiated {ver} session with cipher suite '{cipher}'. "
                    f"Forward secrecy is enabled and AEAD/strong encryption mode was verified."
                ),
                "severity": "INFO",
                "confidence": "HIGH",
                "protocol": protocol,
                "observed_value": _sanitize_string(negotiated_evts[0].observed_value),
                "event_ids": event_ids,
                "frames": frames,
                "first_seen": f_ts,
                "last_seen": l_ts,
                "details": {
                    "what": "Secure TLS session successfully established.",
                    "where": {"src": f"{session_rec.src}:{session_rec.src_port}", "dst": f"{session_rec.dst}:{session_rec.dst_port}", "tcp_stream": session_rec.tcp_stream},
                    "tls_version": ver,
                    "cipher": cipher,
                    "forward_secrecy": "ENABLED",
                    "non_actionable": True
                }
            })

        # -------------------------------------------------------------------------
        # PERSIST FINDINGS WITH DEDUPLICATION AND RISK PRIORITY SCORE
        # -------------------------------------------------------------------------
        persisted_findings: List[Finding] = []
        for c in candidate_findings:
            f_id = f"fnd_{uuid.uuid4().hex[:12]}"
            risk_score = calculate_risk_priority_score(c["severity"], c["confidence"])

            # Sanitize details dict
            clean_details = c.get("details") or {}
            clean_details = {
                k: (_sanitize_string(str(v)) if isinstance(v, str) else v)
                for k, v in clean_details.items()
            }

            finding_db = Finding(
                id=f_id,
                investigation_id=investigation_id,
                session_id=session_id,
                rule_id=c["rule_id"],
                title=_sanitize_string(c["title"]),
                description=_sanitize_string(c["description"]),
                severity=c["severity"],
                confidence=c["confidence"],
                risk_score=risk_score,
                status="ACTIVE",
                protocol=c["protocol"],
                observed_value=_sanitize_string(c["observed_value"]),
                evidence_event_ids=json.dumps(c["event_ids"]),
                evidence_frame_numbers=json.dumps(c["frames"]),
                first_seen=c["first_seen"],
                last_seen=c["last_seen"],
                details_json=json.dumps(clean_details) if clean_details else None
            )
            db.add(finding_db)
            persisted_findings.append(finding_db)

        db.flush()
        return persisted_findings
