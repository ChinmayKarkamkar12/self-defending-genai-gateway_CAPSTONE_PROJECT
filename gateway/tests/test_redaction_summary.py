"""Module 7, security-critical: no raw PII ever reaches the audit log.

Uses the same PII values as module 4's fixtures (tests/test_redaction_stage.py)
and checks every column of the stored entry, the query API's JSON and the
CSV export - not only redaction_summary. CLAUDE.md: "Never log or store raw
PII anywhere ... tested explicitly, not assumed."
"""
import pytest
import respx

from app.db.models import RedactionMode, RedactionPolicy
from tests.audit_helpers import AUTH, all_entries, mock_openai

EMAIL = "jane.smith@example.com"
PHONE = "415-555-2671"
API_KEY_TEXT = "sk-abcdefghijklmnopqrstuvwxyz123456"
CARD = "4111111111111111"
RAW_PII = (EMAIL, PHONE, API_KEY_TEXT, CARD)


def _assert_no_pii(text: str) -> None:
    for value in RAW_PII:
        assert value not in text


@pytest.mark.parametrize("mode", [RedactionMode.MASK, RedactionMode.TOKENIZE])
@respx.mock
async def test_no_raw_pii_in_log_entry(
    client, audit_writer, session_maker, db_session, seeded_team_and_key, mode
):
    team, _ = seeded_team_and_key
    db_session.add(
        RedactionPolicy(
            team_id=team.id,
            enabled_entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "API_KEY", "CREDIT_CARD"],
            mode=mode,
        )
    )
    await db_session.commit()
    # The upstream "answer" repeats PII too: the audit entry must not pick
    # anything up from the response either.
    mock_openai(content=f"Noted, I will email {EMAIL}.")

    response = await client.post(
        "/v1/chat/completions",
        headers=AUTH,
        json={
            # Client-controlled text outside the messages, too.
            "model": f"gpt-4-{EMAIL}",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"Email {EMAIL}, call {PHONE}, key {API_KEY_TEXT}, card {CARD}."
                    ),
                }
            ],
        },
    )
    await audit_writer.flush()
    assert response.status_code == 200

    (entry,) = await all_entries(session_maker)
    # What *is* recorded: entity types and counts only.
    assert entry.redaction_summary == {
        "EMAIL_ADDRESS": 1,
        "PHONE_NUMBER": 1,
        "API_KEY": 1,
        "CREDIT_CARD": 1,
    }
    assert all(isinstance(count, int) for count in entry.redaction_summary.values())
    assert entry.model == "<unrecognized>"

    # Every column of the stored row.
    columns = entry.__table__.columns
    _assert_no_pii(repr({c.name: getattr(entry, c.name) for c in columns}))
    # What the dashboard and an auditor see.
    _assert_no_pii((await client.get("/v1/admin/logs")).text)
    _assert_no_pii((await client.get("/v1/admin/logs/export?format=csv")).text)
