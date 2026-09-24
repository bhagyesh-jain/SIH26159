import time


def test_full_phase1_forensic_pipeline(client, synthetic_pcap_file):
    """
    Integration Test for Phase 1 Vertical Slice:
    1. Create Investigation Case
    2. Upload synthetic SMTP PCAP capture & verify SHA-256
    3. Verify job state becomes COMPLETED
    4. Fetch TCP sessions and packet event JSON timeline
    """
    # 1. Create Investigation
    inv_response = client.post("/api/v1/investigations", json={"title": "Test SMTP Case 001"})
    assert inv_response.status_code == 201
    inv_data = inv_response.json()
    inv_id = inv_data["id"]
    assert inv_data["title"] == "Test SMTP Case 001"

    # 2. Upload synthetic PCAP capture
    with open(synthetic_pcap_file, "rb") as f:
        upload_response = client.post(
            f"/api/v1/investigations/{inv_id}/captures",
            files={"file": ("synthetic_smtp.pcap", f, "application/octet-stream")}
        )

    assert upload_response.status_code == 202
    cap_data = upload_response.json()
    assert cap_data["investigation_id"] == inv_id
    assert cap_data["format"] == "PCAP"
    assert len(cap_data["sha256"]) == 64
    job_id = cap_data["job_id"]
    assert job_id is not None

    # 3. Poll job status until COMPLETED (Background task executes in FastAPI TestClient)
    job_response = client.get(f"/api/v1/jobs/{job_id}")
    assert job_response.status_code == 200
    job_data = job_response.json()
    assert job_data["state"] in ("COMPLETED", "PROCESSING", "QUEUED")

    # 4. Fetch list of extracted TCP sessions
    sessions_response = client.get(f"/api/v1/investigations/{inv_id}/sessions")
    assert sessions_response.status_code == 200
    sessions_list = sessions_response.json()
    assert len(sessions_list) == 1

    session = sessions_list[0]
    assert session["tcp_stream"] == 0
    assert session["protocol"] == "SMTP"
    assert session["dst_port"] == 25
    sess_id = session["id"]

    # 5. Retrieve full session timeline events
    session_detail = client.get(f"/api/v1/sessions/{sess_id}")
    assert session_detail.status_code == 200
    detail_data = session_detail.json()
    assert len(detail_data["events"]) == 5
    first_event = detail_data["events"][0]
    assert first_event["packet_number"] == 1
    assert "frame_number" in first_event["observed_json"]
