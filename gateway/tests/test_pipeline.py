import uuid

import pytest

from app.config import settings
from app.core.context import Decision, RequestContext, StageResult
from app.core.pipeline import StageFailure, run_stages


def make_ctx() -> RequestContext:
    return RequestContext(body={"model": "gpt-4"}, api_key_id=uuid.uuid4(), team_id=uuid.uuid4())


async def test_stages_run_in_order():
    calls: list[str] = []

    async def stage_a(ctx: RequestContext) -> StageResult:
        calls.append("a")
        ctx.metadata["a_ran"] = True
        return StageResult.allow()

    async def stage_b(ctx: RequestContext) -> StageResult:
        calls.append("b")
        assert ctx.metadata.get("a_ran") is True
        return StageResult.allow()

    ctx = make_ctx()
    result = await run_stages([stage_a, stage_b], ctx)

    assert calls == ["a", "b"]
    assert result.decision == Decision.ALLOW


async def test_stages_short_circuit_on_block():
    calls: list[str] = []

    async def blocking_stage(ctx: RequestContext) -> StageResult:
        calls.append("block")
        return StageResult.block("nope")

    async def never_called(ctx: RequestContext) -> StageResult:
        calls.append("never")
        return StageResult.allow()

    result = await run_stages([blocking_stage, never_called], make_ctx())

    assert calls == ["block"]
    assert result.decision == Decision.BLOCK
    assert result.reason == "nope"


async def test_fail_closed_blocks_on_stage_error(monkeypatch):
    monkeypatch.setattr(settings, "FAIL_MODE", "closed")

    async def failing_stage(ctx: RequestContext) -> StageResult:
        raise RuntimeError("boom")

    with pytest.raises(StageFailure):
        await run_stages([failing_stage], make_ctx())


async def test_fail_open_passes_on_stage_error(monkeypatch):
    monkeypatch.setattr(settings, "FAIL_MODE", "open")

    async def failing_stage(ctx: RequestContext) -> StageResult:
        raise RuntimeError("boom")

    result = await run_stages([failing_stage], make_ctx())

    assert result.decision == Decision.ALLOW
