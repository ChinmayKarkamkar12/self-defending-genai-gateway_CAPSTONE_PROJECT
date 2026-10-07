"""FastAPI application entrypoint."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.admin import router as admin_router
from app.api.chat import router as chat_router
from app.api.defense_admin import router as defense_admin_router
from app.config import settings
from app.core.threat.classifier import get_threat_classifier

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger("gateway")


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Load the threat classifier once, at process startup, so the first
    # real request doesn't pay the checkpoint-load cost - see
    # project_plan/05-threat-detection-classifier.md §5 task 8. This
    # deliberately does *not* run during the test suite: tests construct
    # `app` via httpx's ASGITransport without an asgi-lifespan manager, so
    # this lifespan context never executes there - see
    # gateway/tests/test_threat_stage.py's use of
    # set_threat_classifier/reset_threat_classifier instead.
    logger.info("loading threat classifier checkpoint...")
    get_threat_classifier()
    logger.info("threat classifier loaded")
    yield


app = FastAPI(title="Self-Defending GenAI Gateway", version="0.1.0", lifespan=lifespan)
app.include_router(chat_router)
app.include_router(admin_router)
app.include_router(defense_admin_router)


@app.get("/health")
async def health() -> dict:
    """Liveness/readiness probe."""
    return {"status": "ok"}
