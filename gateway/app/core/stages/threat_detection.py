"""Prompt injection / jailbreak scoring stage (pre-call). See
project_plan/05-threat-detection-classifier.md §4.

ARCHITECTURAL INVARIANT, not a style choice: this stage always returns
ALLOW, regardless of the score it computes. It produces a trustworthy
score and nothing else - module 6's bandit stage (which runs immediately
after this one in PRE_CALL_STAGES, see app/core/pipeline.py) is the only
place that turns a threat score into an actual block/allow/redact
decision. Collapsing that boundary here would let this classifier's output
short-circuit the judgment call module 6 is supposed to own. Enforced by
gateway/tests/test_threat_stage.py::test_stage_never_blocks - don't change
this without also revisiting that test's reasoning, not just its assertion.
"""
from typing import Any

from app.core.context import RequestContext, StageResult
from app.core.threat.classifier import get_threat_classifier


def _extract_prompt_text(body: dict[str, Any]) -> str:
    messages = body.get("messages", [])
    parts = [m.get("content") for m in messages if isinstance(m.get("content"), str)]
    return "\n".join(parts)


async def threat_detection_stage(ctx: RequestContext) -> StageResult:
    text = _extract_prompt_text(ctx.body)
    classifier = get_threat_classifier()
    score = classifier.score(text)
    ctx.metadata["threat_score"] = score.as_dict()
    return StageResult.allow()
