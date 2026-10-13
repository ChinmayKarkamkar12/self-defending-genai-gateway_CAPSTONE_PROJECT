"""Shared helpers for the module 7 audit-log tests."""
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import respx
from httpx import Response
from sqlalchemy import select

from app.core.audit.writer import append_entries
from app.core.providers.openai import OPENAI_BASE_URL
from app.db.models import AuditLogEntry, AuditOutcome
from tests.conftest import RAW_TEST_KEY

AUTH = {"Authorization": f"Bearer {RAW_TEST_KEY}"}


def make_record(team_id, api_key_id, **overrides: Any) -> dict[str, Any]:
    """A complete audit record, as build_audit_record would produce."""
    record = {
        "id": uuid.uuid4(),
        "timestamp": datetime.now(UTC),
        "request_id": uuid.uuid4(),
        "team_id": team_id,
        "api_key_id": api_key_id,
        "model": "gpt-4",
        "http_status": 200,
        "outcome": AuditOutcome.ALLOWED,
        "pipeline_stage": None,
        "redaction_summary": {"EMAIL_ADDRESS": 1},
        "threat_score": {"benign": 0.987654321, "prompt_injection": 0.0123, "jailbreak": 1e-05},
        "action_taken": "allow",
        "threat_event_id": uuid.uuid4(),
        "session_id": uuid.uuid4().hex,
        "session_action": "maintain",
        "output_flags": {"system_prompt_leaked": False, "echoed_redaction_tokens": 0},
        "tokens_in": 5,
        "tokens_out": 3,
        "cost_usd": Decimal("0.000330"),
        "latency_ms": 12,
    }
    record.update(overrides)
    return record


async def write_chain(session_maker, team_id, api_key_id, n: int, **overrides) -> None:
    async with session_maker() as session, session.begin():
        await append_entries(
            session, [make_record(team_id, api_key_id, **overrides) for _ in range(n)]
        )


async def all_entries(session_maker) -> list[AuditLogEntry]:
    async with session_maker() as session:
        result = await session.execute(
            select(AuditLogEntry).order_by(AuditLogEntry.sequence_number)
        )
        return list(result.scalars().all())


def mock_openai(content: str = "hi there") -> None:
    """Call inside a @respx.mock test."""
    respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "model": "gpt-4",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3},
            },
        )
    )


def chat_body(content: str = "hello", model: str = "gpt-4", system: str | None = None) -> dict:
    messages = [{"role": "system", "content": system}] if system else []
    messages.append({"role": "user", "content": content})
    return {"model": model, "messages": messages}
