import os
import json
import hashlib
import uuid
import pytest
from pathlib import Path
from backend.app.models.database import SessionLocal, Base, engine, Investigation, Capture, AnalysisJob, Session as DbSession, SecurityEvent, Finding
from backend.app.services.stream_service import process_capture_streams
from backend.app.services.finding_service import FindingService, calculate_risk_priority_score

SYNTHETIC_LAB_DIR = Path(__file__).resolve().parent.parent.parent / "storage" / "pcaps" / "synthetic"

SCENARIO_FILES = [
    "SCN-SMTP-01.pcap",
    "SCN-SMTP-02.pcap",
    "SCN-SMTP-03.pcap",
    "SCN-IMAP-01.pcap",
    "SCN-POP3-01.pcap",
    "SCN-TLS12-BASELINE-01.pcap",
    "SCN-TLS-WEAK-01.pcap",
    "SCN-TLS-SELF-SIGNED-01.pcap",
    "SCN-TLS-EXPIRED-01.pcap",
    "SCN-TLS-INTERRUPTED-01.pcap",
]


def test_stage_f_all_ten_scenarios_per_session(client):
    """
    Ingests all 10 synthetic scenario PCAPs into the database via the production pipeline
    and verifies expected deterministic findings per session.
    """
    db = SessionLocal()
    try:
        inv_res = client.post("/api/v1/investigations", json={"title": "Stage F Benchmark Suite"})
        inv_id = inv_res.json()["id"]

        results = {}
        for pcap_name in SCENARIO_FILES:
            pcap_path = SYNTHETIC_LAB_DIR / pcap_name
            assert pcap_path.exists(), f"PCAP {pcap_name} missing at {pcap_path}"

            with open(pcap_path, "rb") as f:
                up_res = client.post(
                    f"/api/v1/investigations/{inv_id}/captures",
                    files={"file": (pcap_name, f, "application/octet-stream")}
                )
            assert up_res.status_code == 202
            cap_data = up_res.json()
            cap_id = cap_data["id"]

            sessions = db.query(DbSession).filter(DbSession.capture_id == cap_id).order_by(DbSession.tcp_stream.asc()).all()
            
            session_findings = []
            for s in sessions:
                fnds = db.query(Finding).filter(Finding.session_id == s.id).all()
                session_findings.append({
                    "tcp_stream": s.tcp_stream,
                    "protocol": s.protocol,
                    "findings": fnds
                })

            results[pcap_name] = {
                "sessions_count": len(sessions),
                "session_findings": session_findings
            }

        # ---------------------------------------------------------------------
        # PER-SESSION FINDING VERIFICATIONS
        # ---------------------------------------------------------------------

        # 1. SCN-SMTP-01: 2 Sessions (Session 0 POP3, Session 1 SMTP)
        smtp01 = results["SCN-SMTP-01.pcap"]
        assert smtp01["sessions_count"] == 2
        fnds_s0 = smtp01["session_findings"][0]["findings"]
        fnds_s1 = smtp01["session_findings"][1]["findings"]
        assert len(fnds_s0) == 1
        assert fnds_s0[0].rule_id == "EMAIL-PLAINTEXT-NOT-OFFERED-001"
        assert fnds_s0[0].protocol == "POP3"
        assert fnds_s0[0].risk_score == 75

        assert len(fnds_s1) == 1
        assert fnds_s1[0].rule_id == "EMAIL-PLAINTEXT-NOT-OFFERED-001"
        assert fnds_s1[0].protocol == "SMTP"
        assert fnds_s1[0].risk_score == 75

        # 2. SCN-SMTP-02: TLS 1.3 Upgrade
        smtp02_fnds = results["SCN-SMTP-02.pcap"]["session_findings"][0]["findings"]
        assert len(smtp02_fnds) == 1
        assert smtp02_fnds[0].rule_id == "TLS-SECURE-BASELINE-001"
        assert smtp02_fnds[0].severity == "INFO"
        assert smtp02_fnds[0].risk_score == 0

        # 3. SCN-SMTP-03: STARTTLS Offered But Unused
        smtp03_fnds = results["SCN-SMTP-03.pcap"]["session_findings"][0]["findings"]
        assert len(smtp03_fnds) == 1
        assert smtp03_fnds[0].rule_id == "EMAIL-STARTTLS-OFFERED-NOT-USED-001"
        assert smtp03_fnds[0].severity == "CRITICAL"
        assert smtp03_fnds[0].risk_score == 100

        # 4. SCN-IMAP-01: TLS 1.3 Upgrade
        imap01_fnds = results["SCN-IMAP-01.pcap"]["session_findings"][0]["findings"]
        assert len(imap01_fnds) == 1
        assert imap01_fnds[0].rule_id == "TLS-SECURE-BASELINE-001"
        assert imap01_fnds[0].risk_score == 0

        # 5. SCN-POP3-01: TLS 1.3 Upgrade
        pop301_fnds = results["SCN-POP3-01.pcap"]["session_findings"][0]["findings"]
        assert len(pop301_fnds) == 1
        assert pop301_fnds[0].rule_id == "TLS-SECURE-BASELINE-001"
        assert pop301_fnds[0].risk_score == 0

        # 6. SCN-TLS12-BASELINE-01: TLS 1.2 ECDHE
        tls12_fnds = results["SCN-TLS12-BASELINE-01.pcap"]["session_findings"][0]["findings"]
        assert len(tls12_fnds) == 1
        assert tls12_fnds[0].rule_id == "TLS-SECURE-BASELINE-001"
        assert tls12_fnds[0].risk_score == 0

        # 7. SCN-TLS-WEAK-01: TLS 1.2 Static RSA
        weak_fnds = results["SCN-TLS-WEAK-01.pcap"]["session_findings"][0]["findings"]
        assert len(weak_fnds) == 1
        assert weak_fnds[0].rule_id == "TLS-WEAK-STATIC-RSA-001"
        assert weak_fnds[0].severity == "HIGH"
        assert weak_fnds[0].risk_score == 75

        # 8. SCN-TLS-SELF-SIGNED-01: Fatal Alert 48
        self_fnds = results["SCN-TLS-SELF-SIGNED-01.pcap"]["session_findings"][0]["findings"]
        assert len(self_fnds) == 1
        assert self_fnds[0].rule_id == "TLS-ALERT-CERT-OBSERVED-001"
        assert self_fnds[0].confidence == "MEDIUM"
        assert self_fnds[0].risk_score == 60

        # 9. SCN-TLS-EXPIRED-01: Fatal Alert 45
        exp_fnds = results["SCN-TLS-EXPIRED-01.pcap"]["session_findings"][0]["findings"]
        assert len(exp_fnds) == 1
        assert exp_fnds[0].rule_id == "TLS-ALERT-CERT-OBSERVED-001"
        assert exp_fnds[0].confidence == "MEDIUM"
        assert exp_fnds[0].risk_score == 60

        # 10. SCN-TLS-INTERRUPTED-01: Handshake Failed
        inter_fnds = results["SCN-TLS-INTERRUPTED-01.pcap"]["session_findings"][0]["findings"]
        assert len(inter_fnds) == 1
        assert inter_fnds[0].rule_id == "TLS-HANDSHAKE-FAILED-001"
        assert inter_fnds[0].severity == "MEDIUM"
        assert inter_fnds[0].risk_score == 50

    finally:
        db.close()


def test_evidence_json_array_storage_and_api_deserialization(client, synthetic_pcap_file):
    """
    Verifies that evidence_event_ids and evidence_frame_numbers are stored in DB
    as valid JSON array strings and deserialized to List[str] / List[int] in API response.
    """
    inv = client.post("/api/v1/investigations", json={"title": "JSON Evidence Array Test"}).json()["id"]
    with open(synthetic_pcap_file, "rb") as f:
        up_data = client.post(f"/api/v1/investigations/{inv}/captures", files={"file": ("test.pcap", f, "application/octet-stream")}).json()
    
    # Check DB storage
    db = SessionLocal()
    try:
        cap_id = up_data["id"]
        sess = db.query(DbSession).filter(DbSession.capture_id == cap_id).first()
        fnd_db = db.query(Finding).filter(Finding.session_id == sess.id).first()
        assert fnd_db is not None

        # Verify DB raw storage is valid JSON array string
        parsed_evt_ids = json.loads(fnd_db.evidence_event_ids)
        parsed_frames = json.loads(fnd_db.evidence_frame_numbers)
        assert isinstance(parsed_evt_ids, list)
        assert isinstance(parsed_frames, list)
        assert len(parsed_evt_ids) > 0
        assert len(parsed_frames) > 0
    finally:
        db.close()

    # Check REST API endpoint deserialization
    api_fnds = client.get(f"/api/v1/investigations/{inv}/findings").json()
    assert len(api_fnds) > 0
    fnd_api = api_fnds[0]
    assert isinstance(fnd_api["evidence_event_ids"], list)
    assert isinstance(fnd_api["evidence_frame_numbers"], list)
    assert isinstance(fnd_api["evidence_event_ids"][0], str)
    assert isinstance(fnd_api["evidence_frame_numbers"][0], int)


def test_finding_deduplication_and_idempotency(client, synthetic_pcap_file):
    """
    Verifies that multiple SecurityEvents for a single session produce exactly ONE Finding
    per (session_id, rule_id), and re-analyzing a capture is 100% idempotent.
    """
    db = SessionLocal()
    try:
        inv = client.post("/api/v1/investigations", json={"title": "Deduplication Test"}).json()["id"]
        with open(synthetic_pcap_file, "rb") as f:
            up_data = client.post(f"/api/v1/investigations/{inv}/captures", files={"file": ("test.pcap", f, "application/octet-stream")}).json()

        cap_id = up_data["id"]
        job_id = up_data["job_id"]

        fnds_run1 = client.get(f"/api/v1/investigations/{inv}/findings").json()
        count_run1 = len(fnds_run1)

        # Re-run process_capture_streams
        process_capture_streams(db, cap_id, job_id)

        fnds_run2 = client.get(f"/api/v1/investigations/{inv}/findings").json()
        count_run2 = len(fnds_run2)

        assert count_run1 == count_run2

        # Verify unique (session_id, rule_id) pairs
        keys = [(f["session_id"], f["rule_id"]) for f in fnds_run2]
        assert len(keys) == len(set(keys))
    finally:
        db.close()


def test_negative_false_positive_assertions(client):
    """
    Verifies critical negative/false-positive constraints:
    1. TLS 1.2 ECDHE baseline does NOT trigger static RSA rule.
    2. TLS 1.3 strong sessions do NOT trigger weak cipher rules.
    3. STARTTLS advertised but unused does NOT claim credential exposure unless credential events exist.
    4. Fatal cert alerts do NOT claim decrypted certificate contents.
    5. Interrupted TLS does NOT produce secure baseline findings.
    """
    db = SessionLocal()
    try:
        inv_id = client.post("/api/v1/investigations", json={"title": "Negative Test Suite"}).json()["id"]

        # 1. SCN-TLS12-BASELINE-01
        pcap_path = SYNTHETIC_LAB_DIR / "SCN-TLS12-BASELINE-01.pcap"
        with open(pcap_path, "rb") as f:
            c12 = client.post(f"/api/v1/investigations/{inv_id}/captures", files={"file": ("baseline12.pcap", f, "application/octet-stream")}).json()
        
        sess12 = db.query(DbSession).filter(DbSession.capture_id == c12["id"]).first()
        fnds12 = db.query(Finding).filter(Finding.session_id == sess12.id).all()
        rule_ids12 = [f.rule_id for f in fnds12]
        assert "TLS-WEAK-STATIC-RSA-001" not in rule_ids12
        assert "TLS-SECURE-BASELINE-001" in rule_ids12

        # 2. SCN-SMTP-03 credential exposure assertion
        pcap_path3 = SYNTHETIC_LAB_DIR / "SCN-SMTP-03.pcap"
        with open(pcap_path3, "rb") as f:
            c03 = client.post(f"/api/v1/investigations/{inv_id}/captures", files={"file": ("smtp03.pcap", f, "application/octet-stream")}).json()
        sess03 = db.query(DbSession).filter(DbSession.capture_id == c03["id"]).first()
        fnd03 = db.query(Finding).filter(Finding.session_id == sess03.id, Finding.rule_id == "EMAIL-STARTTLS-OFFERED-NOT-USED-001").first()
        assert fnd03 is not None
        details03 = json.loads(fnd03.details_json) if fnd03.details_json else {}
        assert details03.get("credential_exposure_observed") is False

        # 3. SCN-TLS-SELF-SIGNED-01 cert visibility assertion
        pcap_path_cert = SYNTHETIC_LAB_DIR / "SCN-TLS-SELF-SIGNED-01.pcap"
        with open(pcap_path_cert, "rb") as f:
            ccert = client.post(f"/api/v1/investigations/{inv_id}/captures", files={"file": ("cert.pcap", f, "application/octet-stream")}).json()
        sess_cert = db.query(DbSession).filter(DbSession.capture_id == ccert["id"]).first()
        fnd_cert = db.query(Finding).filter(Finding.session_id == sess_cert.id).first()
        assert fnd_cert.rule_id == "TLS-ALERT-CERT-OBSERVED-001"
        details_cert = json.loads(fnd_cert.details_json) if fnd_cert.details_json else {}
        assert "passive_limitation" in details_cert
        assert "encrypted on the wire" in details_cert["passive_limitation"]

        # 4. SCN-TLS-INTERRUPTED-01 baseline assertion
        pcap_path_inter = SYNTHETIC_LAB_DIR / "SCN-TLS-INTERRUPTED-01.pcap"
        with open(pcap_path_inter, "rb") as f:
            cinter = client.post(f"/api/v1/investigations/{inv_id}/captures", files={"file": ("inter.pcap", f, "application/octet-stream")}).json()
        sess_inter = db.query(DbSession).filter(DbSession.capture_id == cinter["id"]).first()
        fnds_inter = db.query(Finding).filter(Finding.session_id == sess_inter.id).all()
        rule_ids_inter = [f.rule_id for f in fnds_inter]
        assert "TLS-SECURE-BASELINE-001" not in rule_ids_inter
        assert "TLS-HANDSHAKE-FAILED-001" in rule_ids_inter

    finally:
        db.close()


def test_password_redaction_in_findings(client, synthetic_pcap_file):
    """Verifies plaintext passwords never appear in Finding records or API responses."""
    inv = client.post("/api/v1/investigations", json={"title": "Finding Redaction Test"}).json()["id"]
    with open(synthetic_pcap_file, "rb") as f:
        client.post(f"/api/v1/investigations/{inv}/captures", files={"file": ("test.pcap", f, "application/octet-stream")})

    findings = client.get(f"/api/v1/investigations/{inv}/findings").json()
    for fnd in findings:
        obs = fnd["observed_value"]
        desc = fnd["description"]
        assert "LOGIN " not in obs or "[REDACTED]" in obs
        assert "PASS " not in obs or "[REDACTED]" in obs
        assert "LOGIN " not in desc or "[REDACTED]" in desc
        assert "PASS " not in desc or "[REDACTED]" in desc


def test_tls_alert_precedence_and_suppression():
    """
    Explicitly tests certificate alert precedence & suppression rules:
    A. Certificate alert 45 -> exactly one certificate finding (TLS-ALERT-CERT-OBSERVED-001)
    B. Certificate alert 48 -> exactly one certificate finding (TLS-ALERT-CERT-OBSERVED-001)
    C. TCP RST without cert alert -> exactly one handshake-failed finding (TLS-HANDSHAKE-FAILED-001)
    D. Certificate alert + TCP RST -> cert finding takes precedence (TLS-ALERT-CERT-OBSERVED-001)
    E. Successful TLS -> neither failure finding (TLS-SECURE-BASELINE-001 only)
    """
    db = SessionLocal()
    try:
        inv = Investigation(id=f"inv_test_{uuid.uuid4().hex[:8]}", title="Precedence Test")
        cap = Capture(id=f"cap_test_{uuid.uuid4().hex[:8]}", investigation_id=inv.id, filename="dummy.pcap", sha256="0"*64, bytes=100, format="pcap", stored_path="/tmp/dummy.pcap")
        db.add_all([inv, cap])
        db.flush()

        def _make_session_with_events(events_data):
            sess_id = f"sess_{uuid.uuid4().hex[:8]}"
            sess = DbSession(id=sess_id, capture_id=cap.id, tcp_stream=99, src="10.0.0.1", dst="10.0.0.2", src_port=5000, dst_port=25, protocol="SMTP")
            db.add(sess)
            db.flush()

            for i, ed in enumerate(events_data):
                evt = SecurityEvent(
                    id=f"sevt_{uuid.uuid4().hex[:8]}",
                    session_id=sess.id,
                    event_type=ed["type"],
                    protocol="SMTP",
                    upgrade_status=ed.get("status", "FAILED"),
                    observed_value=ed.get("value", "dummy"),
                    frame_numbers=str(i + 1),
                    details_json=json.dumps(ed.get("details", {}))
                )
                db.add(evt)
            db.flush()
            return sess.id

        # Case A: Alert 45 (Expired)
        sA = _make_session_with_events([{
            "type": "HANDSHAKE_FAILED", "details": {"alert_level": 2, "alert_desc": "45", "reason": "TLS_HANDSHAKE_ABORTED"}
        }])
        fndsA = FindingService.generate_findings_for_session(db, sA)
        assert len(fndsA) == 1
        assert fndsA[0].rule_id == "TLS-ALERT-CERT-OBSERVED-001"

        # Case B: Alert 48 (Unknown CA)
        sB = _make_session_with_events([{
            "type": "HANDSHAKE_FAILED", "details": {"alert_level": 2, "alert_desc": "48", "reason": "TLS_HANDSHAKE_ABORTED"}
        }])
        fndsB = FindingService.generate_findings_for_session(db, sB)
        assert len(fndsB) == 1
        assert fndsB[0].rule_id == "TLS-ALERT-CERT-OBSERVED-001"

        # Case C: TCP RST without cert alert
        sC = _make_session_with_events([{
            "type": "HANDSHAKE_FAILED", "details": {"tcp_reset": True, "reason": "TCP_RST_DURING_HANDSHAKE"}
        }])
        fndsC = FindingService.generate_findings_for_session(db, sC)
        assert len(fndsC) == 1
        assert fndsC[0].rule_id == "TLS-HANDSHAKE-FAILED-001"

        # Case D: Cert alert + TCP RST in same session
        sD = _make_session_with_events([
            {"type": "HANDSHAKE_FAILED", "details": {"alert_level": 2, "alert_desc": "42", "reason": "BAD_CERT"}},
            {"type": "HANDSHAKE_FAILED", "details": {"tcp_reset": True, "reason": "TCP_RST_AFTER_ALERT"}}
        ])
        fndsD = FindingService.generate_findings_for_session(db, sD)
        assert len(fndsD) == 1
        assert fndsD[0].rule_id == "TLS-ALERT-CERT-OBSERVED-001"

        # Case E: Successful TLS (neither failure finding)
        sE = _make_session_with_events([
            {"type": "TLS_NEGOTIATED", "status": "NEGOTIATED", "details": {"tls_version": "TLSv1.3", "selected_cipher": "TLS_AES_256_GCM_SHA384", "forward_secrecy": "ENABLED"}}
        ])
        fndsE = FindingService.generate_findings_for_session(db, sE)
        assert len(fndsE) == 1
        assert fndsE[0].rule_id == "TLS-SECURE-BASELINE-001"

    finally:
        db.close()

