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

This stage runs *before* pii_redaction_stage, so it sees raw PII. It must
never let request text reach a log line - see ThreatDetectionError.
"""
import asyncio
import logging
from typing import Any

from app.core.context import RequestContext, StageResult
from app.core.messages import message_text
from app.core.threat.classifier import get_threat_classifier

logger = logging.getLogger("gateway.threat")


class ThreatDetectionError(Exception):
    """Raised in place of whatever the tokenizer/model raised.

    Carries only the original exception's type name. The shared pipeline
    runner logs `repr(exc)` for any failing stage, and a library exception
    can embed the input text it choked on - which here would be the raw,
    not-yet-redacted prompt. Same containment as pii_redaction_stage's
    RedactionError.
    """

    def __init__(self, original_type: str):
        super().__init__(f"threat classifier failed ({original_type})")


def _message_texts(body: dict[str, Any]) -> list[str]:
    texts = [message_text(m) for m in body.get("messages", []) if isinstance(m, dict)]
    return [t for t in texts if t] or [""]


async def threat_detection_stage(ctx: RequestContext) -> StageResult:
    texts = _message_texts(ctx.body)
    classifier = get_threat_classifier()

    failure_type: str | None = None
    try:
        # Inference is CPU/GPU-bound (~20ms GPU, ~160ms CPU); running it on
        # the event loop would stall every other in-flight request.
        result = await asyncio.to_thread(classifier.score_texts, texts)
    except Exception as exc:  # noqa: BLE001 - see ThreatDetectionError
        failure_type = type(exc).__name__

    # Raised outside the `except` block so the original exception isn't
    # attached as __context__ - see app/config.py's _load_settings.
    if failure_type is not None:
        logger.error("threat_detection_stage failed (%s)", failure_type)
        raise ThreatDetectionError(failure_type)

    ctx.metadata["threat_score"] = result.score.as_dict()
    ctx.metadata["threat_scan"] = {"windows": result.windows, "truncated": result.truncated}
    return StageResult.allow()
