"""De-duplicates overlapping spans between the Presidio and custom regex
detection layers. See project_plan/04-pii-redaction.md §3.

Two spans "overlap" when their [start, end) ranges intersect at all. Among
overlapping spans, we keep exactly one: prefer higher score, then the wider
span (covers more of the underlying value), so a low-confidence Presidio
guess doesn't survive next to a high-confidence regex match on the same
text, and a redaction doesn't need to run twice over the same characters.
"""
from app.core.redaction.spans import Span


def _overlaps(a: Span, b: Span) -> bool:
    return a.start < b.end and b.start < a.end


def merge_spans(spans: list[Span]) -> list[Span]:
    ordered = sorted(spans, key=lambda s: (-s.score, -len(s), s.start))
    kept: list[Span] = []
    for span in ordered:
        if any(_overlaps(span, existing) for existing in kept):
            continue
        kept.append(span)
    return sorted(kept, key=lambda s: s.start)
