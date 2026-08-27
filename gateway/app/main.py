"""FastAPI application entrypoint.

Bare app skeleton for module 1 — no gateway/proxy logic yet, just wiring
and a health-check endpoint. See project_plan/01-repo-and-conventions.md.
"""
import logging

from fastapi import FastAPI

from app.config import settings

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger("gateway")

app = FastAPI(title="Self-Defending GenAI Gateway", version="0.1.0")


@app.get("/health")
async def health() -> dict:
    """Liveness/readiness probe."""
    return {"status": "ok"}
