import uuid
import datetime
from pathlib import Path
from backend.app.models.database import Base, engine, SessionLocal, Capture, AnalysisJob, Session as DbSessionModel, Event
from backend.app.services.stream_service import process_capture_streams

def test_phase1_ingest_synthetic_smtp_starttls_pcap(tmp_path):
    """Verifies that Phase 1 backend ingests a synthetic SMTP STARTTLS PCAP without error."""
    pcap_path = Path(__file__).resolve().parent.parent.parent / "storage" / "pcaps" / "synthetic" / "SCN-SMTP-02.pcap"
    assert pcap_path.exists(), f"Synthetic PCAP missing at {pcap_path}"

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        capture_id = f"cap_test_{uuid.uuid4().hex[:8]}"
        job_id = f"job_test_{uuid.uuid4().hex[:8]}"

        cap = Capture(
            id=capture_id,
            investigation_id="inv_test_lab",
            filename="SCN-SMTP-02.pcap",
            sha256="dummy_sha256",
            bytes=pcap_path.stat().st_size,
            format="pcap",
            stored_path=str(pcap_path),
            uploaded_at=datetime.datetime.utcnow(),
        )
        db.add(cap)

        job = AnalysisJob(
            id=job_id,
            capture_id=capture_id,
            state="QUEUED",
            started_at=datetime.datetime.utcnow(),
        )
        db.add(job)
        db.commit()

        process_capture_streams(db, capture_id, job_id)

        db.refresh(job)
        assert job.state == "COMPLETED"

        sessions = db.query(DbSessionModel).filter(DbSessionModel.capture_id == capture_id).all()
        assert len(sessions) == 1
        assert sessions[0].protocol == "SMTP"
    finally:
        db.close()
