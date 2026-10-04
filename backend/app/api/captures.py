import uuid
import datetime
from typing import List
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
    res.status = "QUEUED"
    res.sessions_count = 0
    return res


@router.get("/investigations/{investigation_id}/captures", response_model=List[CaptureResponse])
def list_investigation_captures(investigation_id: str, db: DbSession = Depends(get_db)):
    """
    Returns all PCAP/PCAPNG captures uploaded to an investigation with analysis job status and session counts.
    """
    investigation = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation case not found.")

    captures = db.query(Capture).filter(Capture.investigation_id == investigation_id).order_by(Capture.uploaded_at.desc()).all()

    result = []
    for cap in captures:
        c_res = CaptureResponse.model_validate(cap)
        latest_job = cap.jobs[0] if cap.jobs else None
        if latest_job:
            c_res.job_id = latest_job.id
            c_res.status = latest_job.state
        else:
            c_res.status = "COMPLETED"
        c_res.sessions_count = len(cap.sessions)
        result.append(c_res)

    return result


@router.get("/captures/{capture_id}", response_model=CaptureResponse)
def get_capture_detail(capture_id: str, db: DbSession = Depends(get_db)):
    """
    Returns details and evidence metadata for a specific capture.
    """
    capture = db.query(Capture).filter(Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture file not found.")

    c_res = CaptureResponse.model_validate(capture)
    latest_job = capture.jobs[0] if capture.jobs else None
    if latest_job:
        c_res.job_id = latest_job.id
        c_res.status = latest_job.state
    else:
        c_res.status = "COMPLETED"
    c_res.sessions_count = len(capture.sessions)
    return c_res

