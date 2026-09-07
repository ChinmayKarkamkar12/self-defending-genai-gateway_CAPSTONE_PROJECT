from app.core.auth import authenticate


async def test_valid_key_passes(db_session, seeded_team_and_key):
    team, api_key = seeded_team_and_key

    result = await authenticate("sk-gw-test-key", db_session)

    assert result is not None
    assert result.id == api_key.id
    assert result.team_id == team.id


async def test_invalid_key_rejected(db_session, seeded_team_and_key):
    result = await authenticate("sk-gw-not-a-real-key", db_session)

    assert result is None


async def test_revoked_key_rejected(db_session, seeded_team_and_key):
    _, api_key = seeded_team_and_key
    api_key.revoked = True
    db_session.add(api_key)
    await db_session.commit()

    result = await authenticate("sk-gw-test-key", db_session)

    assert result is None
