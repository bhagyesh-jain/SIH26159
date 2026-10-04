import uuid
import json
import datetime
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session as DbSession

from backend.app.models.database import Investigation, Capture, Session, Finding, SecurityEvent


def test_intelligence_endpoint_valid_and_404(client: TestClient, db_session: DbSession):
    """
    1 & 2. Valid investigation returns 200 with complete payload; missing investigation returns 404.
    """
    # Missing investigation -> 404
    resp_404 = client.get(f"/api/v1/investigations/inv_missing_{uuid.uuid4().hex[:8]}/intelligence")
    assert resp_404.status_code == 404
    assert "not found" in resp_404.json()["detail"].lower()

    # Valid investigation
    inv_id = f"inv_intel_val_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="Intelligence Valid Test", status="ACTIVE")
    db_session.add(inv)
    db_session.commit()

    resp = client.get(f"/api/v1/investigations/{inv_id}/intelligence")
    assert resp.status_code == 200
    data = resp.json()
    assert data["investigation_id"] == inv_id
    assert "risk_summary" in data
    assert "protocol_exposure" in data
    assert "pattern_summary" in data
    assert "insights" in data


def test_intelligence_empty_investigation(client: TestClient, db_session: DbSession):
    """
    3. Empty investigation (no captures/sessions/findings) returns 200 with zeroed metrics and empty insight arrays.
    """
    inv_id = f"inv_intel_empty_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="Empty Intelligence Test", status="ACTIVE")
    db_session.add(inv)
    db_session.commit()

    resp = client.get(f"/api/v1/investigations/{inv_id}/intelligence")
    assert resp.status_code == 200
    data = resp.json()

    assert data["risk_summary"]["highest_risk_score"] == 0
    assert data["risk_summary"]["active_findings_count"] == 0
    assert data["risk_summary"]["affected_sessions_count"] == 0
    assert data["pattern_summary"]["repeated_rules"] == []
    assert data["pattern_summary"]["affected_sessions_count"] == 0
    assert data["insights"] == []


def test_intelligence_investigation_isolation(client: TestClient, db_session: DbSession):
    """
    4. Data isolation: findings in Investigation A do not leak into Investigation B.
    """
    inv_a_id = f"inv_iso_intel_A_{uuid.uuid4().hex[:8]}"
    inv_b_id = f"inv_iso_intel_B_{uuid.uuid4().hex[:8]}"
    inv_a = Investigation(id=inv_a_id, title="Case A", status="ACTIVE")
    inv_b = Investigation(id=inv_b_id, title="Case B", status="ACTIVE")
    db_session.add_all([inv_a, inv_b])

    cap_a = Capture(id=f"cap_A_{uuid.uuid4().hex[:8]}", investigation_id=inv_a_id, filename="cap_a.pcap", stored_path="pA", sha256="a"*64, bytes=100, format="PCAP")
    cap_b = Capture(id=f"cap_B_{uuid.uuid4().hex[:8]}", investigation_id=inv_b_id, filename="cap_b.pcap", stored_path="pB", sha256="b"*64, bytes=200, format="PCAP")
    db_session.add_all([cap_a, cap_b])

    s_a = Session(id=f"s_a_{uuid.uuid4().hex[:8]}", capture_id=cap_a.id, tcp_stream=0, src="1.1.1.1", dst="2.2.2.2", src_port=100, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    s_b = Session(id=f"s_b_{uuid.uuid4().hex[:8]}", capture_id=cap_b.id, tcp_stream=0, src="3.3.3.3", dst="4.4.4.4", src_port=101, dst_port=110, protocol="POP3", completeness="COMPLETE")
    db_session.add_all([s_a, s_b])

    f_a = Finding(
        id=f"f_a_{uuid.uuid4().hex[:8]}",
        investigation_id=inv_a_id,
        session_id=s_a.id,
        rule_id="EMAIL-PLAINTEXT-NOT-OFFERED-001",
        title="Plaintext SMTP",
        description="No STARTTLS",
        severity="CRITICAL",
        confidence="HIGH",
        risk_score=75,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="MAIL FROM:<a@test.local>",
        evidence_event_ids=json.dumps(["sevt_a1"]),
        evidence_frame_numbers=json.dumps([1]),
    )
    db_session.add(f_a)
    db_session.commit()

    # Query B's intelligence
    resp_b = client.get(f"/api/v1/investigations/{inv_b_id}/intelligence")
    assert resp_b.status_code == 200
    data_b = resp_b.json()

    assert data_b["risk_summary"]["active_findings_count"] == 0
    assert data_b["insights"] == []


def test_intelligence_determinism_and_ordering(client: TestClient, db_session: DbSession):
    """
    5, 6, & 7. Same DB state -> identical intelligence payload; deterministic ordering (risk DESC, ID ASC); deterministic IDs.
    """
    inv_id = f"inv_det_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="Determinism Case", status="ACTIVE")
    db_session.add(inv)

    cap = Capture(id=f"cap_det_{uuid.uuid4().hex[:8]}", investigation_id=inv_id, filename="det.pcap", stored_path="p", sha256="c"*64, bytes=500, format="PCAP")
    db_session.add(cap)

    # 2 sessions for Plaintext (Risk 75)
    s1 = Session(id=f"s_det1_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=0, src="10.0.0.1", dst="10.0.0.2", src_port=1000, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    s2 = Session(id=f"s_det2_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=1, src="10.0.0.3", dst="10.0.0.2", src_port=1001, dst_port=25, protocol="SMTP", completeness="COMPLETE")

    # 2 sessions for STARTTLS Bypass (Risk 100)
    s3 = Session(id=f"s_det3_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=2, src="10.0.0.4", dst="10.0.0.2", src_port=1002, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    s4 = Session(id=f"s_det4_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=3, src="10.0.0.5", dst="10.0.0.2", src_port=1003, dst_port=25, protocol="SMTP", completeness="COMPLETE")

    db_session.add_all([s1, s2, s3, s4])

    f1 = Finding(
        id=f"f_p1_{uuid.uuid4().hex[:8]}",
        investigation_id=inv_id,
        session_id=s1.id,
        rule_id="EMAIL-PLAINTEXT-NOT-OFFERED-001",
        title="Plaintext 1",
        description="No STARTTLS",
        severity="CRITICAL",
        confidence="HIGH",
        risk_score=75,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="MAIL FROM:<a@test.local>",
        evidence_event_ids=json.dumps(["evt_p1"]),
        evidence_frame_numbers=json.dumps([5]),
    )
    f2 = Finding(
        id=f"f_p2_{uuid.uuid4().hex[:8]}",
        investigation_id=inv_id,
        session_id=s2.id,
        rule_id="EMAIL-PLAINTEXT-NOT-OFFERED-001",
        title="Plaintext 2",
        description="No STARTTLS",
        severity="CRITICAL",
        confidence="HIGH",
        risk_score=75,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="MAIL FROM:<b@test.local>",
        evidence_event_ids=json.dumps(["evt_p2"]),
        evidence_frame_numbers=json.dumps([8]),
    )

    f3 = Finding(
        id=f"f_b1_{uuid.uuid4().hex[:8]}",
        investigation_id=inv_id,
        session_id=s3.id,
        rule_id="EMAIL-STARTTLS-OFFERED-NOT-USED-001",
        title="Bypass 1",
        description="Bypass",
        severity="CRITICAL",
        confidence="HIGH",
        risk_score=100,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="AUTH LOGIN [REDACTED]",
        evidence_event_ids=json.dumps(["evt_b1"]),
        evidence_frame_numbers=json.dumps([10]),
    )
    f4 = Finding(
        id=f"f_b2_{uuid.uuid4().hex[:8]}",
        investigation_id=inv_id,
        session_id=s4.id,
        rule_id="EMAIL-STARTTLS-OFFERED-NOT-USED-001",
        title="Bypass 2",
        description="Bypass",
        severity="CRITICAL",
        confidence="HIGH",
        risk_score=100,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="AUTH LOGIN [REDACTED]",
        evidence_event_ids=json.dumps(["evt_b2"]),
        evidence_frame_numbers=json.dumps([14]),
    )

    db_session.add_all([f1, f2, f3, f4])
    db_session.commit()

    resp1 = client.get(f"/api/v1/investigations/{inv_id}/intelligence")
    resp2 = client.get(f"/api/v1/investigations/{inv_id}/intelligence")

    assert resp1.status_code == 200
    assert resp2.status_code == 200

    d1 = resp1.json()
    d2 = resp2.json()

    # Compare excluding timestamp
    d1_clean = {k: v for k, v in d1.items() if k != "generated_at"}
    d2_clean = {k: v for k, v in d2.items() if k != "generated_at"}
    assert d1_clean == d2_clean

    # Verify deterministic ordering: Highest risk (100) first, then (75)
    insights = d1["insights"]
    assert len(insights) == 2
    assert insights[0]["id"] == "INTEL-REPEATED-STARTTLS-BYPASS-001"
    assert insights[0]["risk_score"] == 100
    assert insights[1]["id"] == "INTEL-REPEATED-PLAINTEXT-001"
    assert insights[1]["risk_score"] == 75


def test_repeated_correlation_patterns(client: TestClient, db_session: DbSession):
    """
    8, 9, 10, 11, 12. Verifies insights generated for repeated plaintext, STARTTLS bypass,
    weak crypto, cert failures, and TLS handshake failures across multiple sessions.
    """
    inv_id = f"inv_patterns_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="All Correlation Patterns", status="ACTIVE")
    db_session.add(inv)

    cap = Capture(id=f"cap_pat_{uuid.uuid4().hex[:8]}", investigation_id=inv_id, filename="all_patterns.pcap", stored_path="p", sha256="d"*64, bytes=2048, format="PCAP")
    db_session.add(cap)

    # Build 2 sessions for each of the 5 rules
    rules = [
        ("EMAIL-PLAINTEXT-NOT-OFFERED-001", "SMTP", 75, "CRITICAL"),
        ("EMAIL-STARTTLS-OFFERED-NOT-USED-001", "SMTP", 100, "CRITICAL"),
        ("TLS-WEAK-STATIC-RSA-001", "SMTP", 75, "HIGH"),
        ("TLS-ALERT-CERT-OBSERVED-001", "IMAP", 75, "HIGH"),
        ("TLS-HANDSHAKE-FAILED-001", "POP3", 50, "MEDIUM"),
    ]

    session_count = 0
    for rule_id, proto, risk, sev in rules:
        s1 = Session(id=f"s_p_{session_count}_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=session_count, src="10.0.0.1", dst="10.0.0.2", src_port=5000+session_count, dst_port=25, protocol=proto, completeness="COMPLETE")
        session_count += 1
        s2 = Session(id=f"s_p_{session_count}_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=session_count, src="10.0.0.1", dst="10.0.0.2", src_port=5000+session_count, dst_port=25, protocol=proto, completeness="COMPLETE")
        session_count += 1
        db_session.add_all([s1, s2])

        f1 = Finding(
            id=f"f_p_{session_count-1}_{uuid.uuid4().hex[:8]}",
            investigation_id=inv_id,
            session_id=s1.id,
            rule_id=rule_id,
            title=f"Title {rule_id}",
            description="Desc",
            severity=sev,
            confidence="HIGH",
            risk_score=risk,
            status="ACTIVE",
            protocol=proto,
            observed_value="obs",
            evidence_event_ids=json.dumps([f"evt_{session_count-1}"]),
            evidence_frame_numbers=json.dumps([session_count-1]),
        )
        f2 = Finding(
            id=f"f_p_{session_count}_{uuid.uuid4().hex[:8]}",
            investigation_id=inv_id,
            session_id=s2.id,
            rule_id=rule_id,
            title=f"Title {rule_id}",
            description="Desc",
            severity=sev,
            confidence="HIGH",
            risk_score=risk,
            status="ACTIVE",
            protocol=proto,
            observed_value="obs",
            evidence_event_ids=json.dumps([f"evt_{session_count}"]),
            evidence_frame_numbers=json.dumps([session_count]),
        )
        db_session.add_all([f1, f2])

    db_session.commit()

    resp = client.get(f"/api/v1/investigations/{inv_id}/intelligence")
    assert resp.status_code == 200
    data = resp.json()

    insight_ids = {i["id"] for i in data["insights"]}
    expected_ids = {
        "INTEL-REPEATED-PLAINTEXT-001",
        "INTEL-REPEATED-STARTTLS-BYPASS-001",
        "INTEL-REPEATED-WEAK-CRYPTO-001",
        "INTEL-REPEATED-CERT-FAILURE-001",
        "INTEL-REPEATED-TLS-FAILURE-001",
    }
    assert insight_ids == expected_ids


def test_no_false_positive_for_single_occurrence_or_info_baseline(client: TestClient, db_session: DbSession):
    """
    13, 14, 15. Single occurrence of a rule does NOT produce a repeated insight;
    INFO secure baseline (TLS-SECURE-BASELINE-001) does NOT become an actionable insight;
    unrelated protocols are segregated.
    """
    inv_id = f"inv_falsepos_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="False Positive Checks", status="ACTIVE")
    db_session.add(inv)

    cap = Capture(id=f"cap_fp_{uuid.uuid4().hex[:8]}", investigation_id=inv_id, filename="fp.pcap", stored_path="p", sha256="e"*64, bytes=1000, format="PCAP")
    db_session.add(cap)

    # 1 single plaintext session (ONLY 1 session, should NOT trigger repeated insight)
    s1 = Session(id=f"s_fp1_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=0, src="10.0.0.1", dst="10.0.0.2", src_port=1000, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    f1 = Finding(
        id=f"f_fp1_{uuid.uuid4().hex[:8]}",
        investigation_id=inv_id,
        session_id=s1.id,
        rule_id="EMAIL-PLAINTEXT-NOT-OFFERED-001",
        title="Single Plaintext",
        description="Desc",
        severity="CRITICAL",
        confidence="HIGH",
        risk_score=75,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="obs",
        evidence_event_ids=json.dumps(["evt_fp1"]),
        evidence_frame_numbers=json.dumps([1]),
    )

    # 2 sessions for TLS-SECURE-BASELINE-001 (INFO baseline, should NOT trigger security insight)
    s2 = Session(id=f"s_fp2_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=1, src="10.0.0.3", dst="10.0.0.2", src_port=1001, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    s3 = Session(id=f"s_fp3_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=2, src="10.0.0.4", dst="10.0.0.2", src_port=1002, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    f2 = Finding(
        id=f"f_fp2_{uuid.uuid4().hex[:8]}",
        investigation_id=inv_id,
        session_id=s2.id,
        rule_id="TLS-SECURE-BASELINE-001",
        title="Secure Baseline 1",
        description="TLS 1.3",
        severity="INFO",
        confidence="HIGH",
        risk_score=0,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="obs",
        evidence_event_ids=json.dumps(["evt_fp2"]),
        evidence_frame_numbers=json.dumps([2]),
    )
    f3 = Finding(
        id=f"f_fp3_{uuid.uuid4().hex[:8]}",
        investigation_id=inv_id,
        session_id=s3.id,
        rule_id="TLS-SECURE-BASELINE-001",
        title="Secure Baseline 2",
        description="TLS 1.3",
        severity="INFO",
        confidence="HIGH",
        risk_score=0,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="obs",
        evidence_event_ids=json.dumps(["evt_fp3"]),
        evidence_frame_numbers=json.dumps([3]),
    )

    db_session.add_all([s1, s2, s3, f1, f2, f3])
    db_session.commit()

    resp = client.get(f"/api/v1/investigations/{inv_id}/intelligence")
    assert resp.status_code == 200
    data = resp.json()

    # Zero insights generated (since single occurrence != repeated, and INFO baseline != actionable security insight)
    assert data["insights"] == []
    assert data["pattern_summary"]["repeated_rules"] == []


def test_evidence_provenance_and_incomplete_quality_state(client: TestClient, db_session: DbSession):
    """
    16, 17, 18, 19. Supporting finding IDs, session IDs, event IDs, and frame numbers are accurate.
    Incomplete session marks evidence_state as INCOMPLETE.
    """
    inv_id = f"inv_prov_intel_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="Provenance Intelligence", status="ACTIVE")
    db_session.add(inv)

    cap = Capture(id=f"cap_prov_{uuid.uuid4().hex[:8]}", investigation_id=inv_id, filename="prov.pcap", stored_path="p", sha256="f"*64, bytes=1000, format="PCAP")
    db_session.add(cap)

    s1 = Session(id=f"s_pr1_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=0, src="10.0.0.1", dst="10.0.0.2", src_port=1000, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    s2 = Session(id=f"s_pr2_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=1, src="10.0.0.3", dst="10.0.0.2", src_port=1001, dst_port=25, protocol="SMTP", completeness="INCOMPLETE")
    db_session.add_all([s1, s2])

    f1 = Finding(
        id=f"f_pr1_{uuid.uuid4().hex[:8]}",
        investigation_id=inv_id,
        session_id=s1.id,
        rule_id="EMAIL-PLAINTEXT-NOT-OFFERED-001",
        title="Plaintext 1",
        description="No STARTTLS",
        severity="CRITICAL",
        confidence="HIGH",
        risk_score=75,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="obs",
        evidence_event_ids=json.dumps(["sevt_01"]),
        evidence_frame_numbers=json.dumps([4, 5]),
        details_json=json.dumps({"remediation": "Mandate TLS encryption."}),
    )
    f2 = Finding(
        id=f"f_pr2_{uuid.uuid4().hex[:8]}",
        investigation_id=inv_id,
        session_id=s2.id,
        rule_id="EMAIL-PLAINTEXT-NOT-OFFERED-001",
        title="Plaintext 2",
        description="No STARTTLS",
        severity="CRITICAL",
        confidence="HIGH",
        risk_score=75,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="obs",
        evidence_event_ids=json.dumps(["sevt_02"]),
        evidence_frame_numbers=json.dumps([12]),
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    resp = client.get(f"/api/v1/investigations/{inv_id}/intelligence")
    assert resp.status_code == 200
    data = resp.json()

    insights = data["insights"]
    assert len(insights) == 1
    insight = insights[0]

    assert insight["id"] == "INTEL-REPEATED-PLAINTEXT-001"
    assert sorted(insight["supporting_finding_ids"]) == sorted([f1.id, f2.id])
    assert sorted(insight["supporting_session_ids"]) == sorted([s1.id, s2.id])
    assert sorted(insight["supporting_event_ids"]) == ["sevt_01", "sevt_02"]
    assert insight["supporting_frame_numbers"] == [4, 5, 12]
    assert insight["evidence_state"] == "INCOMPLETE"  # Marked INCOMPLETE due to s2 completeness
    assert insight["remediation"] == "Mandate TLS encryption."


def test_intelligence_security_contract_no_secrets(client: TestClient, db_session: DbSession):
    """
    20, 21, 22, 23, 24. Intelligence response must not leak filesystem paths, credentials,
    private keys, or raw unredacted authentication payloads.
    """
    inv_id = f"inv_sec_intel_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="Security Contract Test", status="ACTIVE")
    db_session.add(inv)

    secret_path = "D:\\Storage\\Private\\secret_capture.pcap"
    cap = Capture(id=f"cap_sec_{uuid.uuid4().hex[:8]}", investigation_id=inv_id, filename="secret.pcap", stored_path=secret_path, sha256="9"*64, bytes=1000, format="PCAP")
    db_session.add(cap)

    s1 = Session(id=f"s_sec1_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=0, src="10.0.0.1", dst="10.0.0.2", src_port=1000, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    s2 = Session(id=f"s_sec2_{uuid.uuid4().hex[:8]}", capture_id=cap.id, tcp_stream=1, src="10.0.0.3", dst="10.0.0.2", src_port=1001, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    db_session.add_all([s1, s2])

    f1 = Finding(
        id=f"f_sec1_{uuid.uuid4().hex[:8]}",
        investigation_id=inv_id,
        session_id=s1.id,
        rule_id="EMAIL-STARTTLS-OFFERED-NOT-USED-001",
        title="Bypass 1",
        description="Bypass",
        severity="CRITICAL",
        confidence="HIGH",
        risk_score=100,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="AUTH LOGIN [REDACTED]",
        evidence_event_ids=json.dumps(["sevt_s1"]),
        evidence_frame_numbers=json.dumps([1]),
    )
    f2 = Finding(
        id=f"f_sec2_{uuid.uuid4().hex[:8]}",
        investigation_id=inv_id,
        session_id=s2.id,
        rule_id="EMAIL-STARTTLS-OFFERED-NOT-USED-001",
        title="Bypass 2",
        description="Bypass",
        severity="CRITICAL",
        confidence="HIGH",
        risk_score=100,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="AUTH LOGIN [REDACTED]",
        evidence_event_ids=json.dumps(["sevt_s2"]),
        evidence_frame_numbers=json.dumps([2]),
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    resp = client.get(f"/api/v1/investigations/{inv_id}/intelligence")
    assert resp.status_code == 200
    text_content = resp.text

    forbidden_terms = ["stored_path", "Private", "secret_capture"]
    for term in forbidden_terms:
        assert term not in text_content, f"Security leakage detected for term '{term}' in intelligence response."
