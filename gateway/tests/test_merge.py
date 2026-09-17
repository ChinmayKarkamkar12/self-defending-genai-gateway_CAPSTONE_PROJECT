from app.core.redaction.merge import merge_spans
from app.core.redaction.spans import Span


def test_overlapping_spans_deduplicated():
    spans = [Span(0, 16, "PERSON", 0.6), Span(0, 16, "API_KEY", 1.0)]

    merged = merge_spans(spans)

    assert len(merged) == 1
    assert merged[0].entity_type == "API_KEY"


def test_non_overlapping_spans_both_kept():
    spans = [Span(0, 5, "PERSON", 0.6), Span(10, 20, "EMAIL_ADDRESS", 1.0)]

    merged = merge_spans(spans)

    assert len(merged) == 2


def test_partial_overlap_keeps_higher_score():
    spans = [Span(0, 10, "PHONE_NUMBER", 0.4), Span(5, 15, "US_SSN", 0.9)]

    merged = merge_spans(spans)

    assert len(merged) == 1
    assert merged[0].entity_type == "US_SSN"
