import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from app.db.models import Team, UsageRecord


async def _make_usage_record(db_session, team_id, api_key_id, *, timestamp, model="gpt-4o"):
    record = UsageRecord(
        api_key_id=api_key_id,
        team_id=team_id,
        model=model,
        tokens_in=100,
        tokens_out=50,
        cost_usd=Decimal("0.001000"),
        timestamp=timestamp,
    )
    db_session.add(record)
    await db_session.commit()
    return record


async def test_usage_query_filters_by_team_and_date(client, db_session, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    other_team = Team(name="Other Team")
    db_session.add(other_team)
    await db_session.flush()

    now = datetime.now(UTC)
    await _make_usage_record(db_session, team.id, api_key.id, timestamp=now - timedelta(days=5))
    in_range = await _make_usage_record(db_session, team.id, api_key.id, timestamp=now)
    await _make_usage_record(db_session, other_team.id, uuid.uuid4(), timestamp=now)

    response = await client.get(
        "/v1/admin/usage",
        params={
            "team_id": str(team.id),
            "from": (now - timedelta(days=1)).isoformat(),
            "to": (now + timedelta(days=1)).isoformat(),
        },
    )

    assert response.status_code == 200
    ids = [row["id"] for row in response.json()]
    assert ids == [str(in_range.id)]


async def test_get_budget_404_when_unconfigured(client, seeded_team_and_key):
    team, _ = seeded_team_and_key
    response = await client.get(f"/v1/admin/budget/{team.id}")
    assert response.status_code == 404


async def test_put_and_get_budget_round_trip(client, seeded_team_and_key):
    team, _ = seeded_team_and_key

    put_response = await client.put(
        f"/v1/admin/budget/{team.id}",
        json={"period": "daily", "limit_usd": "25.00", "rate_limit_rps": 10},
    )
    assert put_response.status_code == 200
    body = put_response.json()
    assert body["team_id"] == str(team.id)
    assert body["limit_usd"] == "25.00"
    assert body["current_spend_usd"] == "0"
    assert body["remaining_usd"] == "25.00"

    get_response = await client.get(f"/v1/admin/budget/{team.id}")
    assert get_response.status_code == 200
    assert get_response.json()["rate_limit_rps"] == 10
