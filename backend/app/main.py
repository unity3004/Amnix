"""AMNIX FastAPI application entrypoint."""

from fastapi import FastAPI

from app.api.events import router as events_router
from app.api.health import router as health_router
from app.core.config import get_settings

settings = get_settings()

app = FastAPI(
    title="AMNIX",
    description="AI-powered Security Operations Copilot",
    debug=settings.debug,
)

app.include_router(health_router)
app.include_router(events_router)
