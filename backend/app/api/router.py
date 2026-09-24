from fastapi import APIRouter
from backend.app.api.health import router as health_router
from backend.app.api.investigations import router as investigations_router
from backend.app.api.captures import router as captures_router
from backend.app.api.jobs import router as jobs_router
from backend.app.api.sessions import router as sessions_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health_router, tags=["Health"])
api_router.include_router(investigations_router, tags=["Investigations"])
api_router.include_router(captures_router, tags=["Captures"])
api_router.include_router(jobs_router, tags=["Jobs"])
api_router.include_router(sessions_router, tags=["Sessions"])
