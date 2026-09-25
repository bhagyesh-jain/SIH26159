import sys
import uuid
import datetime
from pathlib import Path

# Add workspace root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.models.database import Base, engine, SessionLocal, Capture, AnalysisJob, Session as DbSessionModel, Event

def validate_synthetic_pcap(pcap_filename: str = "SCN-SMTP-02.pcap"):
    pcap_path = Path(__file__).resolve().parent.parent / "storage" / "pcaps" / "synthetic" / pcap_filename
    if not pcap_path.exists():
        print(f"[ERROR] PCAP file not found: {pcap_path}")
        sys.exit(1)

    print(f"[Validate] Ingesting {pcap_filename} into Phase 1 Backend pipeline...")

    # Initialize in-memory / dev database schema
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        capture_id = f"cap_test_{uuid.uuid4().hex[:8]}"
        job_id = f"job_test_{uuid.uuid4().hex[:8]}"

        # Record Capture
        cap = Capture(
            id=capture_id,
            investigation_id="inv_test_lab",
            filename=pcap_filename,
            sha256="dummy_hash_for_test",
            bytes=pcap_path.stat().st_size,
            format="pcap",
            stored_path=str(pcap_path),
            uploaded_at=datetime.datetime.utcnow(),
        )
        db.add(cap)

        # Record AnalysisJob
        job = AnalysisJob(
            id=job_id,
            capture_id=capture_id,
            state="QUEUED",
            started_at=datetime.datetime.utcnow(),
        )
        db.add(job)
        db.commit()

        # Run Phase 1 stream service processing
        from backend.app.services.stream_service import process_capture_streams
        process_capture_streams(db, capture_id, job_id)

        # Re-fetch job and sessions
        db.refresh(job)
        sessions = db.query(DbSessionModel).filter(DbSessionModel.capture_id == capture_id).all()

        print(f"[Result] Job status: {job.state}")
        if job.error_code:
            print(f"[Result] Job error: {job.error_code}")
        print(f"[Result] Extracted TCP Sessions: {len(sessions)}")

        for s in sessions:
            events_count = db.query(Event).filter(Event.session_id == s.id).count()
            print(f"  - Session ID: {s.id} | Stream: {s.tcp_stream} | {s.src}:{s.src_port} -> {s.dst}:{s.dst_port} | Protocol: {s.protocol} | Events: {events_count}")

        assert job.state == "COMPLETED", f"Job failed with state: {job.state}, error: {job.error_code}"
        assert len(sessions) > 0, "No TCP sessions were extracted from the PCAP"
        classified_protos = [s.protocol for s in sessions]
        print(f"[SUCCESS] Classified protocols: {classified_protos}")
        assert any(p != "UNKNOWN" for p in classified_protos), "Expected known protocol classification"

        print(f"\n[SUCCESS] Phase 1 backend successfully processed {pcap_filename} without regression!")

    finally:
        db.close()

if __name__ == "__main__":
    target_pcap = sys.argv[1] if len(sys.argv) > 1 else "SCN-SMTP-02.pcap"
    validate_synthetic_pcap(target_pcap)
