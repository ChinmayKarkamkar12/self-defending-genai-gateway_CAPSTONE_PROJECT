"""Async Redis client wiring.

Built lazily as a module-level singleton (same pattern as
`app.db.session.engine`) so import doesn't require Redis to be reachable.
Tests override the `get_redis` FastAPI dependency with a fakeredis instance
instead of talking to a real Redis server.
"""
from redis.asyncio import Redis

from app.config import settings

_redis: Redis | None = None


def _client() -> Redis:
    global _redis
    if _redis is None:
        _redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


async def get_redis() -> Redis:
    return _client()
