"""RedactionPolicy lookup, plus the stage's default when a team has none.
See project_plan/04-pii-redaction.md §2, §4.

Unlike budget policies (module 3, opt-in - no policy means unrestricted),
a missing RedactionPolicy does *not* mean "don't redact": PII protection is
a security control, so teams without an explicit policy still get a sane
default rather than passing prompts through unredacted.
"""
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import RedactionMode, RedactionPolicy

DEFAULT_ENABLED_ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "PERSON",
    "CREDIT_CARD",
    "US_SSN",
    "API_KEY",
    "IP_ADDRESS",
]
DEFAULT_MODE = RedactionMode.MASK


async def get_redaction_policy(db: AsyncSession, team_id: UUID) -> RedactionPolicy | None:
    result = await db.execute(select(RedactionPolicy).where(RedactionPolicy.team_id == team_id))
    return result.scalar_one_or_none()


def effective_entities(policy: RedactionPolicy | None) -> list[str]:
    return policy.enabled_entities if policy is not None else DEFAULT_ENABLED_ENTITIES


def effective_mode(policy: RedactionPolicy | None) -> RedactionMode:
    return policy.mode if policy is not None else DEFAULT_MODE
