from fastapi import APIRouter
from backend.app.core.tshark_discovery import get_tshark_version

router = APIRouter()


@router.get("/health")
def get_health_status():
    """
    Returns system health status and TShark executable availability.
    Does not expose sensitive system paths.
    """
    available, version_str, _ = get_tshark_version()
    
    return {
        "status": "healthy",
        "tshark": {
            "available": available,
            "version": version_str if available else "TShark not found"
        }
    }
