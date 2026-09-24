from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DbSession
from backend.app.models.database import get_db, AnalysisJob
from backend.app.schemas.job import JobResponse

router = APIRouter()


@router.get("/jobs/{job_id}", response_model=JobResponse)
def get_job_status(job_id: str, db: DbSession = Depends(get_db)):
    """
    Returns the processing status of an analysis job (QUEUED, PROCESSING, COMPLETED, FAILED).
    """
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found.")
    return job
