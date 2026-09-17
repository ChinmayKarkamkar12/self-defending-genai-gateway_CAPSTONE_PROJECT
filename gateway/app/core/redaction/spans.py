"""Shared span type for detected PII, used by both detection layers (Presidio
and the custom regex layer) and by merge.py's de-duplication. See
project_plan/04-pii-redaction.md §3.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Span:
    """A single detected entity's location in text. Deliberately carries no
    copy of the matched substring - callers slice the original text
    themselves at the point of use, so a `Span` can be logged or passed
    around without risking a raw PII value leaking into it by accident.
    """

    start: int
    end: int
    entity_type: str
    score: float

    def __len__(self) -> int:
        return self.end - self.start
