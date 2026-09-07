"""Types shared by every pipeline stage. See project_plan/02-gateway-core-proxy.md §4."""
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from uuid import UUID


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    MODIFY = "modify"


@dataclass
class RequestContext:
    """Carries a single request through the pipeline.

    `metadata` is mutable and shared across stages so a later stage (or the
    audit logger) can read what an earlier stage decided (threat score,
    redaction map, etc.) without stages depending on each other directly.
    """

    body: dict[str, Any]
    api_key_id: UUID
    team_id: UUID
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class StageResult:
    decision: Decision
    reason: str | None = None
    modified_body: dict[str, Any] | None = None

    @classmethod
    def allow(cls) -> "StageResult":
        return cls(decision=Decision.ALLOW)

    @classmethod
    def block(cls, reason: str) -> "StageResult":
        return cls(decision=Decision.BLOCK, reason=reason)

    @classmethod
    def modify(cls, new_body: dict[str, Any]) -> "StageResult":
        return cls(decision=Decision.MODIFY, modified_body=new_body)
