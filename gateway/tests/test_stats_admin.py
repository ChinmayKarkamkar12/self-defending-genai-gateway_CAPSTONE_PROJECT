"""Module 8: summary statistics for the dashboard (/v1/admin/stats/*)."""
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from app.core.audit.writer import append_entries
from app.db.models import AuditOutcome, Team, UsageRecord
from tests.audit_helpers import make_record

NOW = datetime.now(UTC)
WINDOW = {
    "from": (NOW - timedelta(hours=1)).isoformat(),
    "to": (NOW + timedelta(hours=1)).isoformat(),
}


def _r(team, key, outcome, *, pii=None, action="allow", cost="0", at=None):
    return make_record(
        team.id,
        key.id,
        outcome=outcome,
        redaction_summary=pii or {},
        action_taken=action,
        cost_usd=Decimal(cost),
        timestamp=at or NOW,
    )


async def _seed(session_maker, team, key):
    """One request of each kind the route has to tell apart."""
    records = [
        _r(team, key, AuditOutcome.ALLOWED, cost="0.002"),
        _r(team, key, AuditOutcome.ALLOWED, cost="0.001"),
        _r(team, key, AuditOutcome.ALLOWED, pii={"EMAIL_ADDRESS": 2, "PHONE_NUMBER": 1}),
        _r(team, key, AuditOutcome.ALLOWED, action="redact_and_allow"),
        _r(team, key, AuditOutcome.REJECTED_STREAMING, action="not_evaluated"),
        _r(team, key, AuditOutcome.BLOCKED_SESSION_LOCKED, action="not_evaluated"),
        _r(team, key, AuditOutcome.BLOCKED_BUDGET, action="not_evaluated"),
        _r(team, key, AuditOutcome.BLOCKED_RATE_LIMIT, action="not_evaluated"),
        _r(team, key, AuditOutcome.BLOCKED_THREAT, action="block"),
        _r(team, key, AuditOutcome.BLOCKED_THREAT, action="block"),
        _r(team, key, AuditOutcome.ESCALATED, action="escalate_to_human"),
        _r(team, key, AuditOutcome.UPSTREAM_ERROR),
        _r(team, key, AuditOutcome.BLOCKED_OUTPUT_LEAK),
        _r(team, key, AuditOutcome.PIPELINE_ERROR, action="not_evaluated"),
        # Outside the window: must not be counted.
        _r(team, key, AuditOutcome.ALLOWED, at=NOW - timedelta(days=3)),
    ]
    async with session_maker() as session, session.begin():
        await append_entries(session, records)


async def test_overview_route_and_decisions(client, session_maker, seeded_team_and_key):
    team, key = seeded_team_and_key
    await _seed(session_maker, team, key)

    body = (await client.get("/v1/admin/stats/overview", params=WINDOW)).json()

    assert body["total_requests"] == 14
    assert body["answered"] == 4
    assert body["errors"] == 1
    route = {stage["key"]: stage for stage in body["route"]}
    assert [stage["key"] for stage in body["route"]] == [
        "intake", "session", "budget", "screening", "provider", "output",
    ]
    # Each stage sees what got past the previous ones (errors excluded).
    assert route["intake"] == {"key": "intake", "reached": 13, "stopped": 1, "cleaned": 0}
    assert route["session"]["reached"] == 12 and route["session"]["stopped"] == 1
    assert route["budget"]["reached"] == 11 and route["budget"]["stopped"] == 2
    assert route["screening"] == {"key": "screening", "reached": 9, "stopped": 3, "cleaned": 2}
    assert route["provider"]["reached"] == 6 and route["provider"]["stopped"] == 1
    assert route["output"]["reached"] == 5 and route["output"]["stopped"] == 1
    # What's left after the last stage is exactly what was answered.
    assert route["output"]["reached"] - route["output"]["stopped"] == body["answered"]

    assert body["decisions"] == {
        "allowed": 2, "cleaned": 2, "held": 1, "refused": 7, "failed": 2,
    }
    assert body["pii_entities"] == {"EMAIL_ADDRESS": 2, "PHONE_NUMBER": 1}
    assert Decimal(body["spend_usd"]) == Decimal("0.003")
    assert len(body["outcomes"]) == len(AuditOutcome)


async def test_overview_defaults_to_today_and_filters_by_team(
    client, session_maker, seeded_team_and_key, db_session
):
    team, key = seeded_team_and_key
    other = Team(name="Other")
    db_session.add(other)
    await db_session.commit()
    async with session_maker() as session, session.begin():
        await append_entries(
            session,
            [
                _r(team, key, AuditOutcome.ALLOWED),
                _r(other, key, AuditOutcome.ALLOWED),
                _r(team, key, AuditOutcome.ALLOWED, at=NOW - timedelta(days=2)),
            ],
        )

    everyone = (await client.get("/v1/admin/stats/overview")).json()
    assert everyone["total_requests"] == 2
    params = {"team_id": str(team.id)}
    one_team = (await client.get("/v1/admin/stats/overview", params=params)).json()
    assert one_team["total_requests"] == 1


async def test_overview_empty_window(client):
    body = (await client.get("/v1/admin/stats/overview")).json()
    assert body["total_requests"] == 0
    assert all(stage["reached"] == 0 for stage in body["route"])
    assert body["decisions"] == {d: 0 for d in ("allowed", "cleaned", "held", "refused", "failed")}


async def test_timeline_buckets(client, session_maker, seeded_team_and_key):
    team, key = seeded_team_and_key
    day = NOW.replace(hour=12, minute=0, second=0, microsecond=0) - timedelta(days=1)
    async with session_maker() as session, session.begin():
        await append_entries(
            session,
            [
                _r(team, key, AuditOutcome.ALLOWED, at=day + timedelta(minutes=5)),
                _r(team, key, AuditOutcome.BLOCKED_THREAT, at=day + timedelta(minutes=50)),
                _r(team, key, AuditOutcome.ESCALATED, at=day + timedelta(hours=2)),
            ],
        )

    body = (await client.get("/v1/admin/stats/timeline", params={"bucket": "hour"})).json()
    assert [b["total"] for b in body["buckets"]] == [2, 1]
    first = body["buckets"][0]
    assert first["decisions"]["allowed"] == 1 and first["decisions"]["refused"] == 1
    assert body["buckets"][1]["decisions"]["held"] == 1

    daily = (await client.get("/v1/admin/stats/timeline", params={"bucket": "day"})).json()
    assert [b["total"] for b in daily["buckets"]] == [3]


async def test_spend_by_bucket_team_and_model(client, db_session, seeded_team_and_key):
    team, key = seeded_team_and_key
    for model, cost in (("gpt-4o", "0.010"), ("gpt-4o", "0.005"), ("local-llama3", "0")):
        db_session.add(
            UsageRecord(
                api_key_id=key.id,
                team_id=team.id,
                model=model,
                tokens_in=10,
                tokens_out=5,
                cost_usd=Decimal(cost),
                timestamp=NOW,
            )
        )
    await db_session.commit()

    body = (await client.get("/v1/admin/stats/spend", params=WINDOW)).json()
    by_model = {p["model"]: p for p in body["points"]}
    assert by_model["gpt-4o"]["requests"] == 2
    assert Decimal(by_model["gpt-4o"]["cost_usd"]) == Decimal("0.015")
    assert by_model["gpt-4o"]["tokens_in"] == 20
    assert Decimal(by_model["local-llama3"]["cost_usd"]) == 0
    assert Decimal(body["total_usd"]) == Decimal("0.015")


async def test_stats_reject_reversed_window(client):
    params = {"from": NOW.isoformat(), "to": (NOW - timedelta(days=1)).isoformat()}
    for path in ("overview", "timeline", "spend"):
        assert (await client.get(f"/v1/admin/stats/{path}", params=params)).status_code == 422


async def test_teams_list(client, seeded_team_and_key):
    team, _ = seeded_team_and_key
    body = (await client.get("/v1/admin/teams")).json()
    assert body == [{"id": str(team.id), "name": team.name}]
