import json
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.models.database import (
    get_db, Investigation, Capture, Session as DbSessionModel, Finding, SecurityEvent
)

client = TestClient(app)


def test_investigation_report_endpoint_full_dataset():
    # Create investigation case
    create_res = client.post("/api/v1/investigations", json={"title": "Report Full Test Case"})
    assert create_res.status_code == 201
    inv_id = create_res.json()["id"]

    db = next(get_db())
    try:
        # Create Capture & Session
        cap = Capture(
            id=f"cap_{inv_id}",
            investigation_id=inv_id,
            filename="report_test.pcap",
            stored_path=f"storage/captures/{inv_id}.pcap",
            sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            bytes=1024,
            format="PCAP",
        )
        db.add(cap)
        db.commit()

        sess = DbSessionModel(
            id=f"sess_{inv_id}_1",
            capture_id=cap.id,
            tcp_stream=1,
            src="10.0.0.1",
            dst="10.0.0.2",
            src_port=50000,
            dst_port=25,
            protocol="SMTP",
            completeness="COMPLETE",
        )
        db.add(sess)
        db.commit()

        # Add Findings with mixed statuses and risk scores
        f1 = Finding(
            id="fnd_002_resolved",
            investigation_id=inv_id,
            session_id=sess.id,
            rule_id="TLS-WEAK-STATIC-RSA-001",
            title="Weak Static RSA Cipher Suite",
            description="Weak static RSA cipher suite used.",
            severity="HIGH",
            confidence="HIGH",
            risk_score=90,
            status="RESOLVED",
            protocol="SMTP",
            observed_value="TLS_RSA_WITH_AES_128_CBC_SHA",
            evidence_event_ids=json.dumps(["sevt_1"]),
            evidence_frame_numbers=json.dumps([10]),
        )

        f2 = Finding(
            id="fnd_001_active",
            investigation_id=inv_id,
            session_id=sess.id,
            rule_id="EMAIL-STARTTLS-OFFERED-NOT-USED-001",
            title="Plaintext Transmission",
            description="STARTTLS offered but unused.",
            severity="CRITICAL",
            confidence="HIGH",
            risk_score=100,
            status="ACTIVE",
            protocol="SMTP",
            observed_value="AUTH LOGIN [REDACTED]",
            evidence_event_ids=json.dumps(["sevt_1"]),
            evidence_frame_numbers=json.dumps([8, 9]),
        )

        sevt = SecurityEvent(
            id="sevt_1",
            session_id=sess.id,
            event_type="CAPABILITY_ADVERTISED",
            protocol="SMTP",
            upgrade_status="OFFERED_NOT_USED",
            observed_value="250-STARTTLS",
            frame_numbers=json.dumps([8, 9]),
            evidence_source="TSHARK_REASSEMBLED_STREAM",
            completeness_status="COMPLETE",
        )

        db.add_all([f1, f2, sevt])
        db.commit()

        # Call GET /api/v1/investigations/{id}/report
        res = client.get(f"/api/v1/investigations/{inv_id}/report")
        assert res.status_code == 200

        data = res.json()
        assert data["investigation_id"] == inv_id
        assert data["title"] == "Report Full Test Case"
        assert data["evidence_scope"] == "COMPLETE"
        assert "summary" in data
        assert len(data["findings"]) == 2
        assert len(data["security_events"]) == 1

        # Check deterministic ordering: ACTIVE (fnd_001_active) before RESOLVED (fnd_002_resolved)
        assert data["findings"][0]["id"] == "fnd_001_active"
        assert data["findings"][1]["id"] == "fnd_002_resolved"

        # Check credential redaction
        assert "[REDACTED]" in data["findings"][0]["observed_value"]

    finally:
        db.close()


def test_investigation_report_empty_investigation():
    create_res = client.post("/api/v1/investigations", json={"title": "Empty Report Test Case"})
    assert create_res.status_code == 201
    inv_id = create_res.json()["id"]

    res = client.get(f"/api/v1/investigations/{inv_id}/report")
    assert res.status_code == 200

    data = res.json()
    assert data["investigation_id"] == inv_id
    assert data["evidence_scope"] == "COMPLETE"
    assert data["findings"] == []
    assert data["security_events"] == []


def test_investigation_report_nonexistent_id():
    res = client.get("/api/v1/investigations/nonexistent_inv_999/report")
    assert res.status_code == 404
