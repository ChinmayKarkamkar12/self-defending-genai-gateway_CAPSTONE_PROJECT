"""Module 7: GET /v1/admin/logs, /logs/verify, /logs/export."""
import csv
import io
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from app.core.audit.writer import append_entries
from app.db.models import AuditOutcome
from tests.audit_helpers import all_entries, make_record

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


async def _seed(session_maker, team, api_key, other_team_id):
    """Six entries: two teams, three days, three actions."""
    records = [
        make_record(team.id, api_key.id, timestamp=T0, action_taken="allow"),
        make_record(
            team.id,
            api_key.id,
            timestamp=T0 + timedelta(days=1),
            action_taken="block",
            outcome=AuditOutcome.BLOCKED_THREAT,
            http_status=422,
        ),
        make_record(team.id, api_key.id, timestamp=T0 + timedelta(days=2), action_taken="allow"),
        make_record(other_team_id, api_key.id, timestamp=T0, action_taken="allow"),
        make_record(
            other_team_id,
            api_key.id,
            timestamp=T0 + timedelta(days=1),
            action_taken="block",
            outcome=AuditOutcome.BLOCKED_THREAT,
            http_status=422,
        ),
        make_record(
            team.id,
            api_key.id,
            timestamp=T0 + timedelta(days=2),
            action_taken="redact_and_allow",
        ),
    ]
    async with session_maker() as session, session.begin():
        await append_entries(session, records)


async def test_query_filters_work(client, session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    other = uuid.uuid4()
    await _seed(session_maker, team, api_key, other)

    async def seqs(**params):
        response = await client.get("/v1/admin/logs", params=params)
        assert response.status_code == 200
        return [e["sequence_number"] for e in response.json()["entries"]]

    assert await seqs() == [6, 5, 4, 3, 2, 1]  # newest first
    assert await seqs(team_id=str(team.id)) == [6, 3, 2, 1]
    assert await seqs(team_id=str(other)) == [5, 4]
    assert await seqs(action="block") == [5, 2]
    assert await seqs(team_id=str(team.id), action="block") == [2]
    assert await seqs(outcome="blocked_threat") == [5, 2]
    day1 = (T0 + timedelta(days=1)).isoformat()
    assert await seqs(**{"from": day1}) == [6, 5, 3, 2]
    assert await seqs(to=day1) == [5, 4, 2, 1]
    assert await seqs(**{"from": day1, "to": day1}) == [5, 2]


async def test_pagination_walks_every_entry_once(client, session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    await _seed(session_maker, team, api_key, uuid.uuid4())

    seen, cursor = [], None
    while True:
        params = {"limit": 4} if cursor is None else {"limit": 4, "before_sequence": cursor}
        page = (await client.get("/v1/admin/logs", params=params)).json()
        seen += [e["sequence_number"] for e in page["entries"]]
        cursor = page["next_before_sequence"]
        if cursor is None:
            break
    assert seen == [6, 5, 4, 3, 2, 1]


async def test_entry_shape(client, session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    await _seed(session_maker, team, api_key, uuid.uuid4())

    entry = (await client.get("/v1/admin/logs", params={"limit": 1})).json()["entries"][0]

    for field in ("entry_hash", "prev_hash", "threat_score", "redaction_summary", "cost_usd"):
        assert field in entry
    assert len(entry["entry_hash"]) == 64


async def test_verify_endpoint(client, session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    await _seed(session_maker, team, api_key, uuid.uuid4())

    ok = (await client.get("/v1/admin/logs/verify")).json()
    assert ok["valid"] is True
    assert ok["first_broken_entry"] is None
    assert ok["entry_count"] == 6

    target = (await all_entries(session_maker))[1]
    async with session_maker() as session, session.begin():
        await session.execute(
            text("UPDATE audit_log_entries SET action_taken = 'allow' WHERE id = :id"),
            {"id": target.id.hex},
        )
    broken = (await client.get("/v1/admin/logs/verify")).json()
    assert broken["valid"] is False
    assert broken["first_broken_entry"] == str(target.id)
    assert broken["first_broken_sequence"] == 2


async def test_csv_export(client, session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    await _seed(session_maker, team, api_key, uuid.uuid4())

    response = await client.get(
        "/v1/admin/logs/export", params={"format": "csv", "action": "block"}
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert [int(r["sequence_number"]) for r in rows] == [2, 5]  # oldest first
    assert {r["action_taken"] for r in rows} == {"block"}
    assert rows[0]["entry_hash"] == (await all_entries(session_maker))[1].entry_hash


async def test_csv_export_neutralizes_formulas(client, session_maker, seeded_team_and_key):
    """CSV injection: a cell starting with = + - @ runs as a formula when
    the export is opened in a spreadsheet."""
    team, api_key = seeded_team_and_key
    async with session_maker() as session, session.begin():
        await append_entries(
            session,
            [make_record(team.id, api_key.id, session_id='=HYPERLINK("http://evil")')],
        )

    response = await client.get("/v1/admin/logs/export")

    (row,) = list(csv.DictReader(io.StringIO(response.text)))
    assert row["session_id"] == "'=HYPERLINK(\"http://evil\")"


async def test_export_rejects_unknown_format(client):
    response = await client.get("/v1/admin/logs/export", params={"format": "xlsx"})
    assert response.status_code == 422


async def test_reversed_date_range_is_rejected(client):
    # A swapped range must be an error, not an empty result that looks
    # like "nothing happened".
    params = {"from": "2026-10-02T00:00:00Z", "to": "2026-10-01T00:00:00Z"}
    for path in ("/v1/admin/logs", "/v1/admin/logs/export"):
        response = await client.get(path, params=params)
        assert response.status_code == 422, path
