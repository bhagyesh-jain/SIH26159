import pytest
from pathlib import Path
from backend.app.models.database import SessionLocal, Base, engine, Investigation, Capture, Session as DbSession, Finding

SYNTHETIC_LAB_DIR = Path(__file__).resolve().parent.parent.parent / "storage" / "pcaps" / "synthetic"


def upload_pcap(client, inv_id: str, pcap_name: str) -> str:
    pcap_path = SYNTHETIC_LAB_DIR / pcap_name
    assert pcap_path.exists(), f"PCAP {pcap_name} missing at {pcap_path}"
    with open(pcap_path, "rb") as f:
        up_res = client.post(
            f"/api/v1/investigations/{inv_id}/captures",
            files={"file": (pcap_name, f, "application/octet-stream")}
        )
    assert up_res.status_code == 202
    return up_res.json()["id"]


def test_summary_empty_investigation(client):
    inv_res = client.post("/api/v1/investigations", json={"title": "Empty Inv"})
    inv_id = inv_res.json()["id"]

    res = client.get(f"/api/v1/investigations/{inv_id}/summary")
    assert res.status_code == 200
    data = res.json()

    assert data["investigation_id"] == inv_id
    assert data["totals"]["captures_count"] == 0
    assert data["totals"]["sessions_count"] == 0
    assert data["totals"]["total_findings_count"] == 0
    assert data["totals"]["actionable_findings_count"] == 0
    assert data["totals"]["informational_findings_count"] == 0
    assert data["totals"]["suppressed_findings_count"] == 0
    assert data["totals"]["resolved_findings_count"] == 0
    assert data["totals"]["affected_sessions_count"] == 0
    assert data["totals"]["highest_risk_score"] == 0


def test_summary_all_ten_synthetic_scenarios(client):
    scenarios = [
        ("SCN-SMTP-01.pcap", {"sessions": 2, "actionable": 2, "affected": 2, "risk": 75, "plaintext": 2}),
        ("SCN-SMTP-02.pcap", {"sessions": 1, "actionable": 0, "affected": 0, "risk": 0, "secure_baseline": 1}),
        ("SCN-SMTP-03.pcap", {"sessions": 1, "actionable": 1, "affected": 1, "risk": 100, "starttls_unused": 1}),
        ("SCN-IMAP-01.pcap", {"sessions": 1, "actionable": 0, "affected": 0, "risk": 0, "secure_baseline": 1}),
        ("SCN-POP3-01.pcap", {"sessions": 1, "actionable": 0, "affected": 0, "risk": 0, "secure_baseline": 1}),
        ("SCN-TLS12-BASELINE-01.pcap", {"sessions": 1, "actionable": 0, "affected": 0, "risk": 0, "secure_baseline": 1}),
        ("SCN-TLS-WEAK-01.pcap", {"sessions": 1, "actionable": 1, "affected": 1, "risk": 75, "weak_rsa": 1}),
        ("SCN-TLS-SELF-SIGNED-01.pcap", {"sessions": 1, "actionable": 1, "affected": 1, "risk": 60, "cert_alert": 1}),
        ("SCN-TLS-EXPIRED-01.pcap", {"sessions": 1, "actionable": 1, "affected": 1, "risk": 60, "cert_alert": 1}),
        ("SCN-TLS-INTERRUPTED-01.pcap", {"sessions": 1, "actionable": 1, "affected": 1, "risk": 50, "handshake_failed": 1}),
    ]

    for pcap_name, expected in scenarios:
        inv_res = client.post("/api/v1/investigations", json={"title": f"Summary Test {pcap_name}"})
        inv_id = inv_res.json()["id"]

        upload_pcap(client, inv_id, pcap_name)

        sum_res = client.get(f"/api/v1/investigations/{inv_id}/summary")
        assert sum_res.status_code == 200
        data = sum_res.json()

        assert data["totals"]["sessions_count"] == expected["sessions"], f"Failed sessions count for {pcap_name}"
        assert data["totals"]["actionable_findings_count"] == expected["actionable"], f"Failed actionable for {pcap_name}"
        assert data["totals"]["affected_sessions_count"] == expected["affected"], f"Failed affected for {pcap_name}"
        assert data["totals"]["highest_risk_score"] == expected["risk"], f"Failed risk score for {pcap_name}"

        if "plaintext" in expected:
            assert data["security_posture"]["plaintext_not_offered_sessions"] == expected["plaintext"]
        if "starttls_unused" in expected:
            assert data["security_posture"]["starttls_offered_not_used_sessions"] == expected["starttls_unused"]
        if "secure_baseline" in expected:
            assert data["security_posture"]["secure_baseline_sessions"] == expected["secure_baseline"]
            assert data["totals"]["informational_findings_count"] == expected["secure_baseline"]
        if "weak_rsa" in expected:
            assert data["security_posture"]["weak_static_rsa_sessions"] == expected["weak_rsa"]
        if "cert_alert" in expected:
            assert data["security_posture"]["certificate_alert_sessions"] == expected["cert_alert"]
        if "handshake_failed" in expected:
            assert data["security_posture"]["handshake_failed_sessions"] == expected["handshake_failed"]


def test_summary_multiple_findings_on_single_session(client):
    db = SessionLocal()
    try:
        inv_res = client.post("/api/v1/investigations", json={"title": "Multi Finding Session Test"})
        inv_id = inv_res.json()["id"]

        cap = Capture(
            id="cap_multi_fnd",
            investigation_id=inv_id,
            filename="multi.pcap",
            sha256="0" * 64,
            bytes=1000,
            format="PCAP",
            stored_path="/tmp/multi.pcap"
        )
        db.add(cap)

        sess = DbSession(
            id="sess_multi_01",
            capture_id="cap_multi_fnd",
            tcp_stream=1,
            src="10.0.0.1",
            dst="10.0.0.2",
            src_port=12345,
            dst_port=25,
            protocol="SMTP",
            completeness="COMPLETE"
        )
        db.add(sess)

        f1 = Finding(
            id="fnd_01",
            investigation_id=inv_id,
            session_id="sess_multi_01",
            rule_id="EMAIL-STARTTLS-OFFERED-NOT-USED-001",
            title="STARTTLS Offered Not Used",
            description="Test desc 1",
            severity="CRITICAL",
            confidence="HIGH",
            risk_score=100,
            status="ACTIVE",
            protocol="SMTP",
            observed_value="STARTTLS",
            evidence_event_ids="[]",
            evidence_frame_numbers="[]"
        )
        f2 = Finding(
            id="fnd_02",
            investigation_id=inv_id,
            session_id="sess_multi_01",
            rule_id="TLS-WEAK-STATIC-RSA-001",
            title="Static RSA",
            description="Test desc 2",
            severity="HIGH",
            confidence="HIGH",
            risk_score=75,
            status="ACTIVE",
            protocol="SMTP",
            observed_value="RSA",
            evidence_event_ids="[]",
            evidence_frame_numbers="[]"
        )
        db.add_all([f1, f2])
        db.commit()

        res = client.get(f"/api/v1/investigations/{inv_id}/summary")
        assert res.status_code == 200
        data = res.json()

        assert data["totals"]["total_findings_count"] == 2
        assert data["totals"]["actionable_findings_count"] == 2
        assert data["totals"]["affected_sessions_count"] == 1
        assert data["totals"]["highest_risk_score"] == 100
        assert data["severity_breakdown"]["critical"] == 1
        assert data["severity_breakdown"]["high"] == 1
    finally:
        db.close()


def test_summary_status_transitions_active_suppressed_resolved(client):
    db = SessionLocal()
    try:
        inv_res = client.post("/api/v1/investigations", json={"title": "Status Transition Test"})
        inv_id = inv_res.json()["id"]

        cap = Capture(id="cap_status", investigation_id=inv_id, filename="s.pcap", sha256="1"*64, bytes=100, format="PCAP", stored_path="/tmp/s.pcap")
        db.add(cap)
        sess = DbSession(id="sess_status", capture_id="cap_status", tcp_stream=1, src="1.1.1.1", dst="2.2.2.2", src_port=1, dst_port=2, protocol="SMTP", completeness="COMPLETE")
        db.add(sess)

        f = Finding(
            id="fnd_status_test",
            investigation_id=inv_id,
            session_id="sess_status",
            rule_id="EMAIL-PLAINTEXT-NOT-OFFERED-001",
            title="Plaintext",
            description="Desc",
            severity="HIGH",
            confidence="HIGH",
            risk_score=75,
            status="ACTIVE",
            protocol="SMTP",
            observed_value="val",
            evidence_event_ids="[]",
            evidence_frame_numbers="[]"
        )
        db.add(f)
        db.commit()

        # ACTIVE
        r1 = client.get(f"/api/v1/investigations/{inv_id}/summary").json()
        assert r1["totals"]["actionable_findings_count"] == 1
        assert r1["totals"]["suppressed_findings_count"] == 0
        assert r1["totals"]["resolved_findings_count"] == 0
        assert r1["totals"]["highest_risk_score"] == 75

        # SUPPRESSED
        f.status = "SUPPRESSED"
        db.commit()
        r2 = client.get(f"/api/v1/investigations/{inv_id}/summary").json()
        assert r2["totals"]["total_findings_count"] == 1
        assert r2["totals"]["actionable_findings_count"] == 0
        assert r2["totals"]["suppressed_findings_count"] == 1
        assert r2["totals"]["resolved_findings_count"] == 0
        assert r2["totals"]["highest_risk_score"] == 0

        # RESOLVED
        f.status = "RESOLVED"
        db.commit()
        r3 = client.get(f"/api/v1/investigations/{inv_id}/summary").json()
        assert r3["totals"]["total_findings_count"] == 1
        assert r3["totals"]["actionable_findings_count"] == 0
        assert r3["totals"]["suppressed_findings_count"] == 0
        assert r3["totals"]["resolved_findings_count"] == 1
        assert r3["totals"]["highest_risk_score"] == 0
    finally:
        db.close()


def test_summary_pagination_independence_large_finding_set(client):
    db = SessionLocal()
    try:
        inv_res = client.post("/api/v1/investigations", json={"title": "Large Finding Set Test"})
        inv_id = inv_res.json()["id"]

        cap = Capture(id="cap_large", investigation_id=inv_id, filename="l.pcap", sha256="2"*64, bytes=500, format="PCAP", stored_path="/tmp/l.pcap")
        db.add(cap)

        # Create 150 findings across 150 sessions
        for i in range(150):
            sess_id = f"sess_large_{i}"
            s = DbSession(id=sess_id, capture_id="cap_large", tcp_stream=i, src="10.0.0.1", dst="10.0.0.2", src_port=1000+i, dst_port=25, protocol="SMTP", completeness="COMPLETE")
            db.add(s)
            f = Finding(
                id=f"fnd_large_{i}",
                investigation_id=inv_id,
                session_id=sess_id,
                rule_id="EMAIL-PLAINTEXT-NOT-OFFERED-001",
                title=f"Finding {i}",
                description="Desc",
                severity="HIGH",
                confidence="HIGH",
                risk_score=75,
                status="ACTIVE",
                protocol="SMTP",
                observed_value="val",
                evidence_event_ids="[]",
                evidence_frame_numbers="[]"
            )
            db.add(f)
        db.commit()

        # Check paginated findings endpoint returns 100 items by default
        paginated_res = client.get(f"/api/v1/investigations/{inv_id}/findings")
        assert len(paginated_res.json()) == 100

        # Check summary endpoint returns exact un-truncated count 150
        sum_res = client.get(f"/api/v1/investigations/{inv_id}/summary")
        assert sum_res.status_code == 200
        data = sum_res.json()

        assert data["totals"]["total_findings_count"] == 150
        assert data["totals"]["actionable_findings_count"] == 150
        assert data["totals"]["affected_sessions_count"] == 150
    finally:
        db.close()


def test_top_findings_priority_and_deterministic_ordering(client):
    db = SessionLocal()
    try:
        inv_res = client.post("/api/v1/investigations", json={"title": "Top Findings Priority Test"})
        inv_id = inv_res.json()["id"]

        cap = Capture(id="cap_top_prio", investigation_id=inv_id, filename="top.pcap", sha256="3"*64, bytes=500, format="PCAP", stored_path="/tmp/top.pcap")
        db.add(cap)

        s = DbSession(id="sess_top_prio", capture_id="cap_top_prio", tcp_stream=1, src="10.0.0.1", dst="10.0.0.2", src_port=1000, dst_port=25, protocol="SMTP", completeness="COMPLETE")
        db.add(s)

        # Create findings in non-sorted insertion order
        f_info = Finding(id="fnd_04_info", investigation_id=inv_id, session_id="sess_top_prio", rule_id="TLS-SECURE-BASELINE-001", title="Info Baseline", description="D", severity="INFO", confidence="HIGH", risk_score=0, status="ACTIVE", protocol="SMTP", observed_value="v", evidence_event_ids="[]", evidence_frame_numbers="[]")
        f_medium = Finding(id="fnd_03_med", investigation_id=inv_id, session_id="sess_top_prio", rule_id="TLS-HANDSHAKE-FAILED-001", title="Medium Handshake", description="D", severity="MEDIUM", confidence="HIGH", risk_score=50, status="ACTIVE", protocol="SMTP", observed_value="v", evidence_event_ids="[]", evidence_frame_numbers="[]")
        f_high_b = Finding(id="fnd_02_high_b", investigation_id=inv_id, session_id="sess_top_prio", rule_id="EMAIL-PLAINTEXT-NOT-OFFERED-001", title="High Plaintext B", description="D", severity="HIGH", confidence="HIGH", risk_score=75, status="ACTIVE", protocol="SMTP", observed_value="v", evidence_event_ids="[]", evidence_frame_numbers="[]")
        f_high_a = Finding(id="fnd_01_high_a", investigation_id=inv_id, session_id="sess_top_prio", rule_id="EMAIL-PLAINTEXT-NOT-OFFERED-001", title="High Plaintext A", description="D", severity="HIGH", confidence="HIGH", risk_score=75, status="ACTIVE", protocol="SMTP", observed_value="v", evidence_event_ids="[]", evidence_frame_numbers="[]")
        f_crit = Finding(id="fnd_00_crit", investigation_id=inv_id, session_id="sess_top_prio", rule_id="EMAIL-STARTTLS-OFFERED-NOT-USED-001", title="Critical STARTTLS", description="D", severity="CRITICAL", confidence="HIGH", risk_score=100, status="ACTIVE", protocol="SMTP", observed_value="v", evidence_event_ids="[]", evidence_frame_numbers="[]")

        db.add_all([f_info, f_medium, f_high_b, f_high_a, f_crit])
        db.commit()

        # Fetch top findings with limit=5 and status=ACTIVE
        res = client.get(f"/api/v1/investigations/{inv_id}/findings?status=ACTIVE&limit=5")
        assert res.status_code == 200
        findings = res.json()

        assert len(findings) == 5
        # Verify ordering places highest risk score first: 100 -> 75 -> 75 -> 50 -> 0
        scores = [f["risk_score"] for f in findings]
        assert scores == [100, 75, 75, 50, 0]

        # Verify deterministic tie-breaking on id.asc() for risk_score=75
        high_ids = [f["id"] for f in findings if f["risk_score"] == 75]
        assert high_ids == ["fnd_01_high_a", "fnd_02_high_b"]
    finally:
        db.close()
