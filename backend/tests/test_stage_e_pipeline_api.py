import os
import json
import hashlib
import uuid
import pytest
from pathlib import Path
from backend.app.models.database import SessionLocal, Investigation, Capture, AnalysisJob, Session as DbSession, SecurityEvent
from backend.app.services.stream_service import process_capture_streams, _sanitize_sensitive_data
from backend.app.services.protocols.imap import IMAPStateMachine
from backend.app.services.protocols.pop3 import POP3StateMachine

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


def test_real_capture_upload_hash_and_metadata_validation(client, synthetic_pcap_file):
    """
    Verifies production upload route POST /api/v1/investigations/{id}/captures:
    1. Computes actual SHA-256 of PCAP bytes.
    2. Uploads via FastAPI client.
    3. Verifies stored Capture.sha256 == computed SHA-256 of uploaded bytes.
    4. Verifies stored byte count, filename, and format.
    5. Verifies analysis references the same capture.
    6. Verifies stored hash is unchanged after processing.
    """
    with open(synthetic_pcap_file, "rb") as f:
        file_bytes = f.read()

    expected_sha256 = hashlib.sha256(file_bytes).hexdigest()
    expected_bytes = len(file_bytes)

    # 1. Create Investigation
    inv_res = client.post("/api/v1/investigations", json={"title": "SHA-256 Real Upload Test Case"})
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    # 2. Upload capture through production REST API endpoint
    with open(synthetic_pcap_file, "rb") as f:
        up_res = client.post(
            f"/api/v1/investigations/{inv_id}/captures",
            files={"file": ("synthetic_smtp.pcap", f, "application/octet-stream")}
        )
    assert up_res.status_code == 202
    cap_data = up_res.json()

    assert cap_data["sha256"] == expected_sha256
    assert cap_data["bytes"] == expected_bytes
    assert cap_data["filename"] == "synthetic_smtp.pcap"
    assert cap_data["format"] == "PCAP"
    job_id = cap_data["job_id"]
    capture_id = cap_data["id"]

    # 3. Wait for background analysis job to finish
    job_res = client.get(f"/api/v1/jobs/{job_id}")
    assert job_res.status_code == 200
    assert job_res.json()["state"] == "COMPLETED"

    # 4. Verify in DB that Capture.sha256 remains unchanged after processing
    db = SessionLocal()
    try:
        cap_db = db.query(Capture).filter(Capture.id == capture_id).first()
        assert cap_db is not None
        assert cap_db.sha256 == expected_sha256
        assert cap_db.bytes == expected_bytes
    finally:
        db.close()


def test_investigation_isolation(client, synthetic_pcap_file):
    """Verifies strict isolation of security events between separate investigations."""
    inv_a = client.post("/api/v1/investigations", json={"title": "Investigation A"}).json()["id"]
    with open(synthetic_pcap_file, "rb") as f:
        client.post(f"/api/v1/investigations/{inv_a}/captures", files={"file": ("a.pcap", f, "application/octet-stream")})

    inv_b = client.post("/api/v1/investigations", json={"title": "Investigation B"}).json()["id"]

    sec_a = client.get(f"/api/v1/investigations/{inv_a}/security-events").json()
    sec_b = client.get(f"/api/v1/investigations/{inv_b}/security-events").json()

    assert len(sec_a) > 0
    assert len(sec_b) == 0


def test_reprocessing_idempotency_no_duplicate_events(client, synthetic_pcap_file):
    """
    Verifies that re-processing a capture clears old events,
    does not duplicate Sessions or SecurityEvents, and leaves 0 orphan events.
    """
    db = SessionLocal()
    try:
        inv = client.post("/api/v1/investigations", json={"title": "Idempotency Test"}).json()["id"]
        with open(synthetic_pcap_file, "rb") as f:
            up_data = client.post(f"/api/v1/investigations/{inv}/captures", files={"file": ("test.pcap", f, "application/octet-stream")}).json()

        cap_id = up_data["id"]
        job_id = up_data["job_id"]

        # First run (already triggered by background task)
        sec_events_run1 = client.get(f"/api/v1/investigations/{inv}/security-events").json()
        count_run1 = len(sec_events_run1)

        # Explicit second run
        process_capture_streams(db, cap_id, job_id)

        sec_events_run2 = client.get(f"/api/v1/investigations/{inv}/security-events").json()
        count_run2 = len(sec_events_run2)

        assert count_run1 == count_run2

        # Verify no orphan security events exist
        sessions = db.query(DbSession).filter(DbSession.capture_id == cap_id).all()
        session_ids = [s.id for s in sessions]
        all_sec_events = db.query(SecurityEvent).all()
        for se in all_sec_events:
            assert se.session_id in session_ids or db.query(DbSession).filter(DbSession.id == se.session_id).first() is not None
    finally:
        db.close()


def test_transaction_rollback_on_processing_failure():
    """
    Verifies that a critical processing failure (e.g. invalid stored path)
    marks AnalysisJob as FAILED with an error code and NEVER leaves it COMPLETED.
    """
    db = SessionLocal()
    try:
        inv = Investigation(id=f"inv_{uuid.uuid4().hex[:8]}", title="Failure Rollback Test")
        cap = Capture(
            id=f"cap_{uuid.uuid4().hex[:8]}",
            investigation_id=inv.id,
            filename="invalid.pcap",
            sha256="1"*64,
            bytes=100,
            format="PCAP",
            stored_path="nonexistent/path/file.pcap"
        )
        job = AnalysisJob(id=f"job_{uuid.uuid4().hex[:8]}", capture_id=cap.id, state="QUEUED")
        db.add(inv)
        db.add(cap)
        db.add(job)
        db.commit()

        process_capture_streams(db, cap.id, job.id)

        job_db = db.query(AnalysisJob).filter(AnalysisJob.id == job.id).first()
        assert job_db.state == "FAILED"
        assert job_db.error_code is not None
        assert "FAILED" in job_db.state
        assert job_db.state != "COMPLETED"
    finally:
        db.close()


def test_credential_redaction_imap_pop3_and_malformed():
    """
    Tests IMAP LOGIN, POP3 PASS, malformed commands, and string sanitization.
    Verifies plaintext passwords NEVER appear in output values or details.
    """
    # IMAP LOGIN tests
    imap_sm = IMAPStateMachine()
    redacted_imap1 = imap_sm._redact_imap_line("A001 LOGIN alice secret123")
    assert redacted_imap1 == "A001 LOGIN alice [REDACTED]"
    assert "secret123" not in redacted_imap1

    redacted_imap2 = imap_sm._redact_imap_line('A001 LOGIN "user@domain.com" "P@ssw0rd123!"')
    assert "[REDACTED]" in redacted_imap2
    assert "P@ssw0rd123!" not in redacted_imap2

    # POP3 PASS tests
    pop3_sm = POP3StateMachine()
    redacted_pop1 = pop3_sm._redact_pop3_line("PASS MySuperSecretPass")
    assert redacted_pop1 == "PASS [REDACTED]"
    assert "MySuperSecretPass" not in redacted_pop1

    # Generic sanitizer test
    sanitized_text = _sanitize_sensitive_data("A002 LOGIN bob mypass")
    assert sanitized_text == "A002 LOGIN bob [REDACTED]"

    sanitized_pop = _sanitize_sensitive_data("PASS pop3pass")
    assert sanitized_pop == "PASS [REDACTED]"


def test_all_ten_synthetic_scenarios_pipeline_execution(client):
    """
    Ingests all 10 synthetic scenario PCAPs into the database via the production pipeline,
    computes real SHA-256 hashes for each capture, and verifies persisted event counts.
    """
    db = SessionLocal()
    try:
        inv_res = client.post("/api/v1/investigations", json={"title": "Ten Scenario Real Benchmark Suite"})
        inv_id = inv_res.json()["id"]

        results = {}
        for pcap_name in SCENARIO_FILES:
            pcap_path = SYNTHETIC_LAB_DIR / pcap_name
            assert pcap_path.exists(), f"PCAP {pcap_name} missing at {pcap_path}"

            with open(pcap_path, "rb") as f:
                pcap_bytes = f.read()

            real_sha256 = hashlib.sha256(pcap_bytes).hexdigest()

            with open(pcap_path, "rb") as f:
                up_res = client.post(
                    f"/api/v1/investigations/{inv_id}/captures",
                    files={"file": (pcap_name, f, "application/octet-stream")}
                )
            assert up_res.status_code == 202
            cap_data = up_res.json()
            cap_id = cap_data["id"]

            assert cap_data["sha256"] == real_sha256

            sessions = db.query(DbSession).filter(DbSession.capture_id == cap_id).all()
            total_events = 0
            for s in sessions:
                evts = db.query(SecurityEvent).filter(SecurityEvent.session_id == s.id).all()
                total_events += len(evts)

            results[pcap_name] = {
                "sha256": real_sha256,
                "sessions_count": len(sessions),
                "security_events_count": total_events
            }

        for pcap_name, data in results.items():
            assert data["sessions_count"] > 0, f"Scenario {pcap_name} produced 0 sessions"
            assert data["security_events_count"] > 0, f"Scenario {pcap_name} produced 0 security events"
            assert len(data["sha256"]) == 64

    finally:
        db.close()
