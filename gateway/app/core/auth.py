"""Gateway API key validation.

Raw keys are never stored or compared — only their SHA-256 hash. The
gateway-issued key is opaque to clients; it is never the same as an
upstream provider key.
"""
import hashlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ApiKey


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


async def authenticate(raw_key: str, db: AsyncSession) -> ApiKey | None:
    """Return the matching, non-revoked ApiKey row, or None if invalid."""
    key_hash = hash_key(raw_key)
    result = await db.execute(
        select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.revoked.is_(False))
    )
    return result.scalar_one_or_none()
