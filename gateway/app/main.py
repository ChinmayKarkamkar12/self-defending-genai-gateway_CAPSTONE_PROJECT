"""FastAPI application entrypoint."""
import logging

from fastapi import FastAPI

from app.api.admin import router as admin_router
from app.api.chat import router as chat_router
from app.config import settings

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger("gateway")

app = FastAPI(title="Self-Defending GenAI Gateway", version="0.1.0")
app.include_router(chat_router)
app.include_router(admin_router)


@app.get("/health")
async def health() -> dict:
    """Liveness/readiness probe."""
    return {"status": "ok"}
