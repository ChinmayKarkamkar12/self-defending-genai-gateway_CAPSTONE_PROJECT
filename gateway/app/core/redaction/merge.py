"""De-duplicates overlapping spans between the Presidio and custom regex
detection layers. See project_plan/04-pii-redaction.md §3.

Two spans "overlap" when their [start, end) ranges intersect at all. Among
overlapping spans, we keep exactly one.

Resolution rule (deliberate, not score-driven):
  1. A regex-layer span for one of REGEX_EXACT_FORMAT_ENTITIES (API_KEY,
     CREDIT_CARD) always wins over any overlapping Presidio span, full stop -
     regardless of what score either one carries. These are exact-format
     detectors (a Luhn-validated card number, a `sk-...`-shaped key): a
     format match is inherently more reliable evidence than a generic NLP
     guess for exactly these entity types, so there's nothing to weigh.
  2. Otherwise, fall back to Presidio's own score (higher wins), then the
     wider span, then earliest start - these are all genuine Presidio
     results at this point, so comparing their scores is comparing like
     with like.

Why not just compare `span.score` across the board: Presidio's score is a
real, calibrated NLP confidence. The regex layer's score
(patterns.py's `_REGEX_MATCH_SCORE`) isn't a probability at all - a regex
either matches or it doesn't - so treating it as directly comparable to
Presidio's score was a real bug: found via a Postgres-backed audit where
Presidio's own built-in CREDIT_CARD recognizer also reports score 1.0,
which tied against the regex layer's hardcoded 1.0 and fell through to an
arbitrary width/position tiebreak instead of a documented rule. Rule 1
above resolves that case (and every other regex-vs-Presidio overlap on
these entity types) deterministically instead of by coincidence.
"""
from app.core.redaction.spans import SOURCE_REGEX, Span

# Entity types where the regex layer's exact-format check is inherently more
# reliable than Presidio's generic NLP guess - see module docstring rule 1.
REGEX_EXACT_FORMAT_ENTITIES = frozenset({"API_KEY", "CREDIT_CARD"})


def _overlaps(a: Span, b: Span) -> bool:
    return a.start < b.end and b.start < a.end


def _is_trusted_regex_match(span: Span) -> bool:
    return span.source == SOURCE_REGEX and span.entity_type in REGEX_EXACT_FORMAT_ENTITIES


def _priority(span: Span) -> tuple:
    # Sorted ascending: trusted regex matches (rank 0) always precede every
    # other span (rank 1), regardless of score. Within a rank, higher score
    # wins, then wider span, then earliest start.
    rank = 0 if _is_trusted_regex_match(span) else 1
    return (rank, -span.score, -len(span), span.start)


def merge_spans(spans: list[Span]) -> list[Span]:
    ordered = sorted(spans, key=_priority)
    kept: list[Span] = []
    for span in ordered:
        if any(_overlaps(span, existing) for existing in kept):
            continue
        kept.append(span)
    return sorted(kept, key=lambda s: s.start)
