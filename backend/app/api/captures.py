import uuid
import datetime
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session as DbSession
from backend.app.models.database import get_db, Investigation, Capture, AnalysisJob
from backend.app.schemas.capture import CaptureResponse
from backend.app.services.capture_service import process_and_save_upload
from backend.app.services.stream_service import process_capture_streams
from backend.app.core.tshark_discovery import get_tshark_version

router = APIRouter()


@router.post("/investigations/{investigation_id}/captures", response_model=CaptureResponse, status_code=202)
def upload_capture(
    investigation_id: str,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: DbSession = Depends(get_db)
):
    """
    Uploads a PCAP or PCAPNG capture file for analysis.
    Validates magic bytes, computes SHA-256 hash, creates immutable storage,
    and queues background analysis job via TShark.
    """
    investigation = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation case not found.")

    # 1. Process upload & calculate hash
    capture_id, sha256_hash, total_bytes, format_str, target_path = process_and_save_upload(file)

    # Check TShark version
    _, tshark_ver, _ = get_tshark_version()

    # 2. Database records
    capture = Capture(
        id=capture_id,
        investigation_id=investigation_id,
        filename=file.filename or "capture.pcap",
        sha256=sha256_hash,
        bytes=total_bytes,
        format=format_str,
        stored_path=str(target_path),
        tshark_version=tshark_ver
    )
    db.add(capture)

    job_id = f"job_{uuid.uuid4().hex[:12]}"
    job = AnalysisJob(
        id=job_id,
        capture_id=capture_id,
        state="QUEUED",
        parser_version="tshark-1.0"
    )
    db.add(job)
    db.commit()
    db.refresh(capture)

    # 3. Trigger background stream processing
    background_tasks.add_task(process_capture_streams, db, capture_id, job_id)

    res = CaptureResponse.model_validate(capture)
    res.job_id = job_id
    return res
