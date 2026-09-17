"""Shared span type for detected PII, used by both detection layers (Presidio
and the custom regex layer) and by merge.py's de-duplication. See
project_plan/04-pii-redaction.md §3.
"""
from dataclasses import dataclass
from typing import Literal

# Which detection layer produced a span. Presidio's score is a real,
# calibrated NLP confidence; the regex layer's isn't a probability at all
# (see patterns.py) - `source` lets merge.py's overlap resolution treat the
# two honestly instead of comparing them as if they were the same kind of
# number. See merge.py's module docstring for the resolution rule this
# feeds.
SOURCE_PRESIDIO = "presidio"
SOURCE_REGEX = "regex"


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
    source: Literal["presidio", "regex"]

    def __len__(self) -> int:
        return self.end - self.start
