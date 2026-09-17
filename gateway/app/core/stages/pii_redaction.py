"""PII redaction stage. See project_plan/04-pii-redaction.md §4.

Reads `ctx.metadata["db"]`, populated by the chat endpoint before the
pipeline runs (same pattern as budget_check_stage). Detects PII in every
string message `content` in the outbound prompt via
app.core.redaction.analyzer, then redacts each detected span according to
the team's RedactionPolicy (or the stage's default - see
app.core.redaction.policy):

  - mask     -> replace with "[REDACTED_<ENTITY_TYPE>]"
  - tokenize -> replace with a unique token, mapping stored in RedactionVault

`ctx.metadata["redaction_map"]` is set to entity-type -> count only, for the
audit logger - never a raw or partial PII value. This is the module's
security-critical invariant (project_plan/04-pii-redaction.md §4, §7):
nothing derived from the detected spans' text ever gets attached to
`ctx.metadata` or logged, only counts and entity types themselves.

That invariant also has to hold on the *failure* path, not just the happy
path: malformed input can make Presidio/spaCy raise (confirmed during the
module-4 audit - a lone UTF-16 surrogate character crashes spaCy's
tokenizer with a `UnicodeEncodeError`). The shared pipeline runner
(app/core/pipeline.py's `_run_stage`) logs any stage failure via
`repr(exc)`, with no awareness that *this* stage's exceptions might carry
request content. Rather than trust every current and future exception type
from Presidio/spaCy/regex to never embed matched text in its message, this
module catches its own detection/redaction failures and re-raises
`RedactionError`, which deliberately carries only the failing exception's
type name - so whatever the shared logger does with it, there's nothing to
leak.
"""
import logging
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import RequestContext, StageResult
from app.core.redaction.analyzer import analyze_text
from app.core.redaction.policy import effective_entities, effective_mode, get_redaction_policy
from app.core.redaction.vault import store_token
from app.db.models import RedactionMode

logger = logging.getLogger("gateway.redaction")


class RedactionError(Exception):
    """Raised when PII detection/redaction fails while processing a
    message. Carries only the failing exception's type name - see module
    docstring - so it's always safe to log via `str()`/`repr()` even by
    generic, content-agnostic pipeline logging.
    """


async def _redact_text(
    db: AsyncSession,
    team_id: UUID,
    text: str,
    enabled_entities: list[str],
    mode: RedactionMode,
) -> tuple[str, dict[str, int]]:
    spans = analyze_text(text, enabled_entities)
    if not spans:
        return text, {}

    counts: dict[str, int] = {}
    # Replace back-to-front so earlier spans' offsets stay valid as the
    # string is rebuilt.
    for span in sorted(spans, key=lambda s: s.start, reverse=True):
        counts[span.entity_type] = counts.get(span.entity_type, 0) + 1
        if mode == RedactionMode.TOKENIZE:
            original_value = text[span.start : span.end]
            replacement = await store_token(db, team_id, span.entity_type, original_value)
        else:
            replacement = f"[REDACTED_{span.entity_type}]"
        text = text[: span.start] + replacement + text[span.end :]

    return text, counts


async def pii_redaction_stage(ctx: RequestContext) -> StageResult:
    db = ctx.metadata["db"]

    policy = await get_redaction_policy(db, ctx.team_id)
    enabled_entities = effective_entities(policy)
    mode = effective_mode(policy)

    messages: list[dict[str, Any]] = ctx.body.get("messages", [])
    redaction_map: dict[str, int] = {}
    new_messages: list[dict[str, Any]] = []
    changed = False
    failure_type: str | None = None

    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            try:
                new_content, counts = await _redact_text(
                    db, ctx.team_id, content, enabled_entities, mode
                )
            except Exception as exc:  # noqa: BLE001 - see RedactionError docstring
                # Deliberately not logging str(exc)/repr(exc) here - see
                # module docstring for why that can't be trusted to never
                # contain request text. Type name only.
                failure_type = type(exc).__name__
                break
            if counts:
                changed = True
                for entity_type, count in counts.items():
                    redaction_map[entity_type] = redaction_map.get(entity_type, 0) + count
                message = {**message, "content": new_content}
        new_messages.append(message)

    # Raised outside the `except` block above, not via `raise ... from exc`
    # inside it - see app/config.py's _load_settings for why: Python
    # auto-attaches the exception currently being handled to a new
    # exception's `__context__` the moment it's raised inside an `except`
    # clause, and merely suppressing that with `from None` doesn't clear
    # `__context__`, only its default-traceback display.
    if failure_type is not None:
        logger.error("pii_redaction_stage failed to process a message (%s)", failure_type)
        raise RedactionError(failure_type)

    if not changed:
        return StageResult.allow()

    ctx.metadata["redaction_map"] = redaction_map
    return StageResult.modify({**ctx.body, "messages": new_messages})
