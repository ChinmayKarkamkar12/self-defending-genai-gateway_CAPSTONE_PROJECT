import pytest

from app.core.context import Decision, RequestContext
from app.core.redaction.vault import resolve_token
from app.core.stages.pii_redaction import RedactionError, pii_redaction_stage
from app.db.models import RedactionMode, RedactionPolicy


def make_ctx(team_id, api_key_id, db, content: str) -> RequestContext:
    body = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": content}],
    }
    ctx = RequestContext(body=body, api_key_id=api_key_id, team_id=team_id)
    ctx.metadata["db"] = db
    return ctx


async def test_mask_mode_replaces_with_placeholder(db_session, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    db_session.add(
        RedactionPolicy(
            team_id=team.id,
            enabled_entities=["EMAIL_ADDRESS", "API_KEY"],
            mode=RedactionMode.MASK,
        )
    )
    await db_session.commit()

    email = "jane.smith@example.com"
    api_key_text = "sk-abcdefghijklmnopqrstuvwxyz123456"
    ctx = make_ctx(
        team.id, api_key.id, db_session, f"Email me at {email}, my key is {api_key_text}."
    )

    result = await pii_redaction_stage(ctx)

    assert result.decision == Decision.MODIFY
    redacted_content = result.modified_body["messages"][0]["content"]
    assert email not in redacted_content
    assert api_key_text not in redacted_content
    assert "[REDACTED_EMAIL_ADDRESS]" in redacted_content
    assert "[REDACTED_API_KEY]" in redacted_content


async def test_tokenize_mode_roundtrip(db_session, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    db_session.add(
        RedactionPolicy(
            team_id=team.id, enabled_entities=["EMAIL_ADDRESS"], mode=RedactionMode.TOKENIZE
        )
    )
    await db_session.commit()

    email = "jane.smith@example.com"
    ctx = make_ctx(team.id, api_key.id, db_session, f"Email me at {email}.")

    result = await pii_redaction_stage(ctx)

    assert result.decision == Decision.MODIFY
    redacted_content = result.modified_body["messages"][0]["content"]
    assert email not in redacted_content

    # Exactly one bracketed token, and it doesn't contain the original value.
    start = redacted_content.index("[REDACTED_EMAIL_ADDRESS_")
    end = redacted_content.index("]", start) + 1
    token = redacted_content[start:end]
    assert email not in token

    resolved = await resolve_token(db_session, token)
    assert resolved == email


async def test_metadata_never_contains_raw_values(db_session, seeded_team_and_key):
    """Security-critical: ctx.metadata["redaction_map"] must contain only
    entity-type counts, never the original PII (or any substring of it),
    since metadata feeds the audit logger (module 7).
    """
    team, api_key = seeded_team_and_key
    db_session.add(
        RedactionPolicy(
            team_id=team.id,
            enabled_entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "API_KEY"],
            mode=RedactionMode.MASK,
        )
    )
    await db_session.commit()

    email = "jane.smith@example.com"
    phone = "415-555-2671"
    api_key_text = "sk-abcdefghijklmnopqrstuvwxyz123456"
    ctx = make_ctx(
        team.id,
        api_key.id,
        db_session,
        f"Email {email}, call {phone}, key {api_key_text}.",
    )

    await pii_redaction_stage(ctx)

    redaction_map = ctx.metadata["redaction_map"]
    assert redaction_map == {"EMAIL_ADDRESS": 1, "PHONE_NUMBER": 1, "API_KEY": 1}

    serialized = repr(redaction_map)
    assert email not in serialized
    assert phone not in serialized
    assert api_key_text not in serialized
    # Only ints/entity-type strings as values - no raw text fragments at all.
    assert all(isinstance(v, int) for v in redaction_map.values())


async def test_disabled_entity_types_not_redacted(db_session, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    db_session.add(
        RedactionPolicy(
            team_id=team.id, enabled_entities=["EMAIL_ADDRESS"], mode=RedactionMode.MASK
        )
    )
    await db_session.commit()

    ctx = make_ctx(team.id, api_key.id, db_session, "My name is Jane Smith.")

    result = await pii_redaction_stage(ctx)

    assert result.decision == Decision.ALLOW
    assert "redaction_map" not in ctx.metadata


async def test_no_policy_uses_default_and_redacts(db_session, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    email = "jane.smith@example.com"
    ctx = make_ctx(team.id, api_key.id, db_session, f"Email me at {email}.")

    result = await pii_redaction_stage(ctx)

    assert result.decision == Decision.MODIFY
    assert email not in result.modified_body["messages"][0]["content"]


async def test_malformed_input_crash_never_leaks_raw_text(db_session, seeded_team_and_key, caplog):
    """Regression test for the module-4 audit finding: a lone UTF-16
    surrogate character reliably crashes spaCy's tokenizer with a
    `UnicodeEncodeError` deep inside Presidio. Confirm that when
    pii_redaction_stage fails, (1) it raises the module's own sanitized
    `RedactionError`, never the raw underlying exception, and (2) none of
    the sensitive text surrounding the malformed character - an email and a
    real-shaped credit card number - appears anywhere in what gets logged.
    """
    team, api_key = seeded_team_and_key
    email = "jane.smith@example.com"
    card = "4111111111111111"
    content = f"contact {email} about \ud800 this, card {card}"
    ctx = make_ctx(team.id, api_key.id, db_session, content)

    with caplog.at_level("ERROR", logger="gateway.redaction"):
        with pytest.raises(RedactionError) as exc_info:
            await pii_redaction_stage(ctx)

    # The exception itself carries only the failing exception's type name.
    assert email not in str(exc_info.value)
    assert card not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None

    # Nothing logged along the way contains the raw sensitive text either.
    assert email not in caplog.text
    assert card not in caplog.text

    # A failed redaction must never have written anything to metadata.
    assert "redaction_map" not in ctx.metadata
