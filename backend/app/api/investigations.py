import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DbSession
from backend.app.models.database import get_db, Investigation
from backend.app.schemas.investigation import InvestigationCreate, InvestigationResponse

router = APIRouter()


@router.post("/investigations", response_model=InvestigationResponse, status_code=201)
def create_investigation(payload: InvestigationCreate, db: DbSession = Depends(get_db)):
    """Creates a new forensic investigation case."""
    inv_id = f"inv_{uuid.uuid4().hex[:12]}"
    investigation = Investigation(
        id=inv_id,
        title=payload.title,
        status="ACTIVE"
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    return investigation


@router.get("/investigations", response_model=List[InvestigationResponse])
def list_investigations(db: DbSession = Depends(get_db)):
    """Lists all active forensic investigation cases."""
    return db.query(Investigation).order_by(Investigation.created_at.desc()).all()


@router.get("/investigations/{investigation_id}", response_model=InvestigationResponse)
def get_investigation(investigation_id: str, db: DbSession = Depends(get_db)):
    """Gets details for a specific investigation case."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation case not found.")
    return inv
