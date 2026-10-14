"""FastAPI application entrypoint."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.admin import router as admin_router
from app.api.audit_admin import router as audit_admin_router
from app.api.chat import router as chat_router
from app.api.defense_admin import router as defense_admin_router
from app.api.session_admin import router as session_admin_router
from app.config import settings
from app.core.audit.writer import get_audit_writer
from app.core.providers.registry import close_upstream_clients, open_upstream_clients
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
    # Module 7: the background worker that chains and writes audit entries.
    # On shutdown it drains what's queued before the process exits.
    audit_writer = get_audit_writer()
    audit_writer.start()
    # One long-lived HTTP client per upstream provider (LIMITATIONS.md L2-2).
    open_upstream_clients()
    yield
    await close_upstream_clients()
    await audit_writer.stop()


app = FastAPI(title="Self-Defending GenAI Gateway", version="0.1.0", lifespan=lifespan)
app.include_router(chat_router)
app.include_router(admin_router)
app.include_router(defense_admin_router)
app.include_router(session_admin_router)
app.include_router(audit_admin_router)


@app.get("/health")
async def health() -> dict:
    """Liveness/readiness probe."""
    return {"status": "ok"}
