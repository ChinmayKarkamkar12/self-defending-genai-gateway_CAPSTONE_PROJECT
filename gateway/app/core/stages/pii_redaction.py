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
"""
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import RequestContext, StageResult
from app.core.redaction.analyzer import analyze_text
from app.core.redaction.policy import effective_entities, effective_mode, get_redaction_policy
from app.core.redaction.vault import store_token
from app.db.models import RedactionMode


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

    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            new_content, counts = await _redact_text(
                db, ctx.team_id, content, enabled_entities, mode
            )
            if counts:
                changed = True
                for entity_type, count in counts.items():
                    redaction_map[entity_type] = redaction_map.get(entity_type, 0) + count
                message = {**message, "content": new_content}
        new_messages.append(message)

    if not changed:
        return StageResult.allow()

    ctx.metadata["redaction_map"] = redaction_map
    return StageResult.modify({**ctx.body, "messages": new_messages})
