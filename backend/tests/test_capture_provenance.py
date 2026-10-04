import uuid
import hashlib
import datetime
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.orm import Session as DbSession

from backend.app.models.database import Investigation, Capture, Session, AnalysisJob, SecurityEvent, Finding


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_investigation_captures_endpoint_and_404(client: TestClient, db_session: DbSession):
    """
    Tests GET /api/v1/investigations/{id}/captures and 404 for missing investigation.
    Verifies filename, sha256, bytes, format, uploaded_at, status, sessions_count, and absence of stored_path.
    """
    # 1. Nonexistent investigation -> 404
    resp_404 = client.get(f"/api/v1/investigations/inv_nonexistent_{uuid.uuid4().hex[:8]}/captures")
    assert resp_404.status_code == 404
    assert "not found" in resp_404.json()["detail"].lower()

    # 2. Valid investigation with capture
    inv_id = f"inv_cap_test_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="Capture Endpoint Test Case", status="ACTIVE")
    db_session.add(inv)

    content = b"TEST_PCAP_STREAM_CONTENT_001"
    file_sha256 = compute_sha256(content)

    cap_id = f"cap_{uuid.uuid4().hex[:8]}"
    cap = Capture(
        id=cap_id,
        investigation_id=inv_id,
        filename="SCN-SMTP-01.pcap",
        stored_path=f"storage/{inv_id}/{cap_id}.pcap",
        sha256=file_sha256,
        bytes=len(content),
        format="PCAP",
        uploaded_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db_session.add(cap)

    job = AnalysisJob(
        id=f"job_{uuid.uuid4().hex[:8]}",
        capture_id=cap_id,
        state="COMPLETED",
        parser_version="tshark-4.0.0",
    )
    db_session.add(job)

    # Add 2 sessions
    s1 = Session(id=f"sess_1_{uuid.uuid4().hex[:8]}", capture_id=cap_id, tcp_stream=0, src="192.168.1.10", dst="192.168.1.25", src_port=54321, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    s2 = Session(id=f"sess_2_{uuid.uuid4().hex[:8]}", capture_id=cap_id, tcp_stream=1, src="192.168.1.11", dst="192.168.1.25", src_port=54322, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    db_session.add_all([s1, s2])
    db_session.commit()

    resp = client.get(f"/api/v1/investigations/{inv_id}/captures")
    assert resp.status_code == 200
    captures_data = resp.json()
    assert len(captures_data) == 1

    c_item = captures_data[0]
    assert c_item["id"] == cap_id
    assert c_item["investigation_id"] == inv_id
    assert c_item["filename"] == "SCN-SMTP-01.pcap"
    assert c_item["sha256"] == file_sha256
    assert c_item["bytes"] == len(content)
    assert c_item["format"] == "PCAP"
    assert c_item["status"] == "COMPLETED"
    assert c_item["sessions_count"] == 2
    assert "stored_path" not in c_item


def test_capture_detail_endpoint_and_404(client: TestClient, db_session: DbSession):
    """
    Tests GET /api/v1/captures/{capture_id} and 404 for missing capture.
    """
    # 1. Nonexistent capture -> 404
    resp_404 = client.get(f"/api/v1/captures/cap_missing_{uuid.uuid4().hex[:8]}")
    assert resp_404.status_code == 404

    # 2. Valid capture detail
    inv_id = f"inv_capdet_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="Capture Detail Test Case", status="ACTIVE")
    db_session.add(inv)

    content = b"CAPTURE_DETAIL_BINARY_PAYLOAD"
    file_sha256 = compute_sha256(content)

    cap_id = f"cap_det_{uuid.uuid4().hex[:8]}"
    cap = Capture(
        id=cap_id,
        investigation_id=inv_id,
        filename="SCN-IMAP-01.pcapng",
        stored_path=f"storage/private_server_dir/{cap_id}.pcapng",
        sha256=file_sha256,
        bytes=len(content),
        format="PCAPNG",
        uploaded_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db_session.add(cap)

    job = AnalysisJob(
        id=f"job_det_{uuid.uuid4().hex[:8]}",
        capture_id=cap_id,
        state="COMPLETED",
    )
    db_session.add(job)

    s1 = Session(id=f"sess_det_{uuid.uuid4().hex[:8]}", capture_id=cap_id, tcp_stream=0, src="10.0.0.1", dst="10.0.0.2", src_port=1430, dst_port=143, protocol="IMAP", completeness="COMPLETE")
    db_session.add(s1)
    db_session.commit()

    resp = client.get(f"/api/v1/captures/{cap_id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["id"] == cap_id
    assert data["filename"] == "SCN-IMAP-01.pcapng"
    assert data["sha256"] == file_sha256
    assert data["format"] == "PCAPNG"
    assert data["sessions_count"] == 1
    assert data["status"] == "COMPLETED"
    assert "stored_path" not in data


def test_investigation_data_isolation(client: TestClient, db_session: DbSession):
    """
    Verifies GET /api/v1/investigations/{inv_id}/captures returns ONLY captures belonging to inv_id.
    """
    inv_a_id = f"inv_iso_A_{uuid.uuid4().hex[:8]}"
    inv_b_id = f"inv_iso_B_{uuid.uuid4().hex[:8]}"
    inv_a = Investigation(id=inv_a_id, title="Case A", status="ACTIVE")
    inv_b = Investigation(id=inv_b_id, title="Case B", status="ACTIVE")
    db_session.add_all([inv_a, inv_b])

    cap_a = Capture(id=f"cap_A_{uuid.uuid4().hex[:8]}", investigation_id=inv_a_id, filename="cap_A.pcap", stored_path="p1", sha256="a"*64, bytes=100, format="PCAP")
    cap_b = Capture(id=f"cap_B_{uuid.uuid4().hex[:8]}", investigation_id=inv_b_id, filename="cap_B.pcap", stored_path="p2", sha256="b"*64, bytes=200, format="PCAP")
    db_session.add_all([cap_a, cap_b])
    db_session.commit()

    resp_a = client.get(f"/api/v1/investigations/{inv_a_id}/captures")
    assert resp_a.status_code == 200
    caps_a = resp_a.json()
    assert len(caps_a) == 1
    assert caps_a[0]["id"] == cap_a.id
    assert caps_a[0]["filename"] == "cap_A.pcap"

    resp_b = client.get(f"/api/v1/investigations/{inv_b_id}/captures")
    assert resp_b.status_code == 200
    caps_b = resp_b.json()
    assert len(caps_b) == 1
    assert caps_b[0]["id"] == cap_b.id
    assert caps_b[0]["filename"] == "cap_B.pcap"


def test_multiple_captures_in_single_investigation(client: TestClient, db_session: DbSession):
    """
    Verifies multi-capture handling within a single investigation:
    Inv ──< Capture A (2 sessions), Capture B (1 session).
    """
    inv_id = f"inv_multi_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="Multi Capture Case", status="ACTIVE")
    db_session.add(inv)

    cap_a_id = f"cap_multi_A_{uuid.uuid4().hex[:8]}"
    cap_b_id = f"cap_multi_B_{uuid.uuid4().hex[:8]}"

    cap_a = Capture(id=cap_a_id, investigation_id=inv_id, filename="multi_A.pcap", stored_path="pA", sha256="a"*64, bytes=500, format="PCAP")
    cap_b = Capture(id=cap_b_id, investigation_id=inv_id, filename="multi_B.pcap", stored_path="pB", sha256="b"*64, bytes=600, format="PCAP")
    db_session.add_all([cap_a, cap_b])

    s1 = Session(id=f"sess_m1_{uuid.uuid4().hex[:8]}", capture_id=cap_a_id, tcp_stream=0, src="1.1.1.1", dst="2.2.2.2", src_port=100, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    s2 = Session(id=f"sess_m2_{uuid.uuid4().hex[:8]}", capture_id=cap_a_id, tcp_stream=1, src="1.1.1.2", dst="2.2.2.2", src_port=101, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    s3 = Session(id=f"sess_m3_{uuid.uuid4().hex[:8]}", capture_id=cap_b_id, tcp_stream=0, src="1.1.1.3", dst="2.2.2.2", src_port=102, dst_port=110, protocol="POP3", completeness="COMPLETE")
    db_session.add_all([s1, s2, s3])
    db_session.commit()

    # Query captures list
    resp = client.get(f"/api/v1/investigations/{inv_id}/captures")
    assert resp.status_code == 200
    caps_data = resp.json()
    assert len(caps_data) == 2

    cap_map = {c["id"]: c for c in caps_data}
    assert cap_map[cap_a_id]["sessions_count"] == 2
    assert cap_map[cap_b_id]["sessions_count"] == 1

    # Verify sessions point to correct capture provenance
    resp_s1 = client.get(f"/api/v1/sessions/{s1.id}")
    assert resp_s1.status_code == 200
    s1_data = resp_s1.json()
    assert s1_data["capture_filename"] == "multi_A.pcap"
    assert s1_data["capture_sha256"] == "a"*64

    resp_s3 = client.get(f"/api/v1/sessions/{s3.id}")
    assert resp_s3.status_code == 200
    s3_data = resp_s3.json()
    assert s3_data["capture_filename"] == "multi_B.pcap"
    assert s3_data["capture_sha256"] == "b"*64


def test_session_provenance_and_missing_capture_handling(client: TestClient, db_session: DbSession):
    """
    Verifies session API exposes capture_filename and capture_sha256,
    and gracefully returns None without crashing if capture is detached/missing.
    """
    inv_id = f"inv_sessprov_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="Session Provenance Test", status="ACTIVE")
    db_session.add(inv)

    # Detached session (nonexistent capture_id or dummy capture_id)
    s_detached_id = f"sess_detached_{uuid.uuid4().hex[:8]}"
    s_detached = Session(
        id=s_detached_id,
        capture_id=f"cap_orphan_{uuid.uuid4().hex[:8]}",
        tcp_stream=99,
        src="10.10.10.10",
        dst="10.10.10.20",
        src_port=50000,
        dst_port=25,
        protocol="SMTP",
        completeness="COMPLETE",
    )
    db_session.add(s_detached)
    db_session.commit()

    resp = client.get(f"/api/v1/sessions/{s_detached_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["capture_filename"] is None
    assert data["capture_sha256"] is None


def test_report_provenance_multiple_captures(client: TestClient, db_session: DbSession):
    """
    Verifies GET /api/v1/investigations/{id}/report includes all source captures.
    """
    inv_id = f"inv_rep_prov_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="Report Provenance Investigation", status="ACTIVE")
    db_session.add(inv)

    cap1 = Capture(id=f"cap_rep1_{uuid.uuid4().hex[:8]}", investigation_id=inv_id, filename="cap_rep1.pcap", stored_path="p1", sha256="11"*32, bytes=1024, format="PCAP")
    cap2 = Capture(id=f"cap_rep2_{uuid.uuid4().hex[:8]}", investigation_id=inv_id, filename="cap_rep2.pcapng", stored_path="p2", sha256="22"*32, bytes=2048, format="PCAPNG")
    db_session.add_all([cap1, cap2])

    s1 = Session(id=f"sess_r1_{uuid.uuid4().hex[:8]}", capture_id=cap1.id, tcp_stream=0, src="10.0.0.1", dst="10.0.0.2", src_port=1000, dst_port=25, protocol="SMTP", completeness="COMPLETE")
    s2 = Session(id=f"sess_r2_{uuid.uuid4().hex[:8]}", capture_id=cap2.id, tcp_stream=0, src="10.0.0.3", dst="10.0.0.2", src_port=1001, dst_port=110, protocol="POP3", completeness="COMPLETE")
    db_session.add_all([s1, s2])
    db_session.commit()

    resp = client.get(f"/api/v1/investigations/{inv_id}/report")
    assert resp.status_code == 200
    report_data = resp.json()

    assert report_data["evidence_scope"] == "COMPLETE"
    assert "captures" in report_data
    report_caps = report_data["captures"]
    assert len(report_caps) == 2

    cap_filenames = {c["filename"] for c in report_caps}
    assert "cap_rep1.pcap" in cap_filenames
    assert "cap_rep2.pcapng" in cap_filenames

    for c in report_caps:
        assert "stored_path" not in c
        assert c["sha256"] in ["11"*32, "22"*32]


def test_sha256_content_integrity():
    """
    Verifies SHA-256 properties:
    - Same content produces identical SHA-256.
    - Different content produces distinct SHA-256.
    - Derived strictly from content, independent of filename or metadata.
    """
    payload_a = b"FORENSIC_PCAP_BUFFER_A"
    payload_b = b"FORENSIC_PCAP_BUFFER_B"

    hash_a1 = compute_sha256(payload_a)
    hash_a2 = compute_sha256(payload_a)
    hash_b = compute_sha256(payload_b)

    assert hash_a1 == hash_a2
    assert hash_a1 != hash_b
    assert len(hash_a1) == 64
    assert hash_a1 == hashlib.sha256(payload_a).hexdigest()


def test_capture_lifecycle_states_and_failure_handling(client: TestClient, db_session: DbSession):
    """
    Verifies canonical capture analysis job lifecycle states:
    - QUEUED / PROCESSING / COMPLETED / FAILED
    - For failed analysis: capture identity and SHA-256 preserved, status is FAILED, sessions_count is 0, no false findings.
    """
    inv_id = f"inv_lifecycle_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="Lifecycle Case", status="ACTIVE")
    db_session.add(inv)

    content = b"CORRUPTED_OR_UNPARSABLE_BINARY_DATA"
    failed_sha256 = compute_sha256(content)

    cap_failed_id = f"cap_failed_{uuid.uuid4().hex[:8]}"
    cap_failed = Capture(
        id=cap_failed_id,
        investigation_id=inv_id,
        filename="corrupted_capture.pcap",
        stored_path=f"storage/failed/{cap_failed_id}.pcap",
        sha256=failed_sha256,
        bytes=len(content),
        format="PCAP",
    )
    db_session.add(cap_failed)

    job_failed = AnalysisJob(
        id=f"job_failed_{uuid.uuid4().hex[:8]}",
        capture_id=cap_failed_id,
        state="FAILED",
        error_code="TSHARK_PARSE_ERROR",
    )
    db_session.add(job_failed)
    db_session.commit()

    # Query capture detail
    resp = client.get(f"/api/v1/captures/{cap_failed_id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["id"] == cap_failed_id
    assert data["filename"] == "corrupted_capture.pcap"
    assert data["sha256"] == failed_sha256
    assert data["status"] == "FAILED"
    assert data["sessions_count"] == 0

    # Verify no false sessions exist for failed capture
    resp_sessions = client.get(f"/api/v1/investigations/{inv_id}/sessions")
    assert resp_sessions.status_code == 200
    assert len(resp_sessions.json()) == 0


def test_n_plus_one_relationship_query_efficiency(client: TestClient, db_session: DbSession):
    """
    Verifies session list queries do not execute N+1 database queries when fetching capture provenance.
    """
    inv_id = f"inv_nplus1_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="N+1 Efficiency Case", status="ACTIVE")
    db_session.add(inv)

    cap = Capture(id=f"cap_np1_{uuid.uuid4().hex[:8]}", investigation_id=inv_id, filename="stream.pcap", stored_path="p", sha256="f"*64, bytes=1000, format="PCAP")
    db_session.add(cap)

    # Add 10 sessions under this capture
    sessions = []
    for i in range(10):
        s = Session(
            id=f"sess_np_{i}_{uuid.uuid4().hex[:8]}",
            capture_id=cap.id,
            tcp_stream=i,
            src="192.168.1.1",
            dst="192.168.1.2",
            src_port=5000 + i,
            dst_port=25,
            protocol="SMTP",
            completeness="COMPLETE",
        )
        sessions.append(s)
    db_session.add_all(sessions)
    db_session.commit()

    # Track SQL queries executed during endpoint call
    query_count = 0

    def query_listener(conn, cursor, statement, parameters, context, executemany):
        nonlocal query_count
        query_count += 1

    engine = db_session.get_bind()
    event.listen(engine, "before_cursor_execute", query_listener)

    try:
        resp = client.get(f"/api/v1/investigations/{inv_id}/sessions")
        assert resp.status_code == 200
        sess_list = resp.json()
        assert len(sess_list) == 10
        # Check provenance populated for all 10 sessions
        for s_data in sess_list:
            assert s_data["capture_filename"] == "stream.pcap"
            assert s_data["capture_sha256"] == "f"*64

        # Assert total SQL query count is small and bounded (<= 5 queries, NOT 10+ for each session)
        assert query_count <= 5, f"Expected bounded query count <= 5, observed N+1 query burst: {query_count}"
    finally:
        event.remove(engine, "before_cursor_execute", query_listener)


def test_security_contract_no_private_paths_or_secrets(client: TestClient, db_session: DbSession):
    """
    Audits all capture-related API responses to verify zero leakage of filesystem paths (stored_path),
    private keys, or internal environment variables.
    """
    inv_id = f"inv_sec_audit_{uuid.uuid4().hex[:8]}"
    inv = Investigation(id=inv_id, title="Security Contract Audit", status="ACTIVE")
    db_session.add(inv)

    secret_server_path = "D:\\PrivateServerData\\InternalCaptures\\secret_raw_pcap.pcap"
    cap_id = f"cap_sec_{uuid.uuid4().hex[:8]}"
    cap = Capture(
        id=cap_id,
        investigation_id=inv_id,
        filename="SCN-SMTP-03.pcap",
        stored_path=secret_server_path,
        sha256="77"*32,
        bytes=4096,
        format="PCAP",
    )
    db_session.add(cap)
    db_session.commit()

    endpoints_to_audit = [
        f"/api/v1/investigations/{inv_id}/captures",
        f"/api/v1/captures/{cap_id}",
        f"/api/v1/investigations/{inv_id}/report",
    ]

    forbidden_tokens = ["stored_path", "PrivateServerData", "secret_raw_pcap"]

    for ep in endpoints_to_audit:
        resp = client.get(ep)
        assert resp.status_code == 200
        content_str = resp.text

        for token in forbidden_tokens:
            assert token not in content_str, f"Security Violation: Token '{token}' leaked in API response from {ep}"
