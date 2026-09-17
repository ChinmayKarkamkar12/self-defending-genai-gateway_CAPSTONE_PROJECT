"""Fernet-encrypted storage for tokenize-mode redaction. See
project_plan/04-pii-redaction.md §2, §6.

Only `store_token`/`resolve_token` touch plaintext PII, and only in memory
for the duration of the encrypt/decrypt call - the DB row only ever holds
`encrypted_value`. No detokenize HTTP endpoint is wired up (see
project_plan/04-pii-redaction.md §2: "don't wire that endpoint up unless a
real use case needs it").
"""
import secrets
from uuid import UUID

from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.models import RedactionVault


def _fernet() -> Fernet:
    return Fernet(settings.REDACTION_VAULT_KEY.encode())


async def store_token(
    db: AsyncSession, team_id: UUID, entity_type: str, original_value: str
) -> str:
    """Encrypt `original_value` and persist it under a freshly generated
    token, returning the token. The token itself is derived from random
    bytes, never from the original value, so it can't be reversed without
    the vault + encryption key.
    """
    token = f"[REDACTED_{entity_type}_{secrets.token_hex(4)}]"
    encrypted_value = _fernet().encrypt(original_value.encode())
    db.add(
        RedactionVault(token=token, encrypted_value=encrypted_value, team_id=team_id)
    )
    await db.flush()
    return token


async def resolve_token(db: AsyncSession, token: str) -> str | None:
    result = await db.execute(select(RedactionVault).where(RedactionVault.token == token))
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return _fernet().decrypt(row.encrypted_value).decode()
