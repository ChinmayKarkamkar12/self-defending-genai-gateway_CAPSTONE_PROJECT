async def test_get_redaction_policy_404_when_unconfigured(client, seeded_team_and_key):
    team, _ = seeded_team_and_key
    response = await client.get(f"/v1/admin/redaction-policy/{team.id}")
    assert response.status_code == 404


async def test_put_and_get_redaction_policy_round_trip(client, seeded_team_and_key):
    team, _ = seeded_team_and_key

    put_response = await client.put(
        f"/v1/admin/redaction-policy/{team.id}",
        json={"enabled_entities": ["EMAIL_ADDRESS", "US_SSN"], "mode": "tokenize"},
    )
    assert put_response.status_code == 200
    body = put_response.json()
    assert body["team_id"] == str(team.id)
    assert body["enabled_entities"] == ["EMAIL_ADDRESS", "US_SSN"]
    assert body["mode"] == "tokenize"

    get_response = await client.get(f"/v1/admin/redaction-policy/{team.id}")
    assert get_response.status_code == 200
    assert get_response.json()["mode"] == "tokenize"
