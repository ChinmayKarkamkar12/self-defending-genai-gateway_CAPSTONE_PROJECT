"""Seed one test Team and ApiKey for local development.

Usage (from gateway/):
    python -m scripts.seed

Prints the raw API key once — it is not recoverable afterwards since only
its hash is stored.
"""
import asyncio
import secrets

from app.core.auth import hash_key
from app.db.models import ApiKey, Team
from app.db.session import async_session_maker


async def seed() -> None:
    raw_key = f"sk-gw-{secrets.token_hex(24)}"

    async with async_session_maker() as session:
        team = Team(name="Local Dev Team")
        session.add(team)
        await session.flush()

        api_key = ApiKey(key_hash=hash_key(raw_key), team_id=team.id, name="local-dev-key")
        session.add(api_key)
        await session.commit()

    print("Seeded team + API key for local development.")
    print(f"  Team ID:  {team.id}")
    print(f"  API key:  {raw_key}")
    print("Store this key now — it cannot be retrieved again.")


if __name__ == "__main__":
    asyncio.run(seed())
