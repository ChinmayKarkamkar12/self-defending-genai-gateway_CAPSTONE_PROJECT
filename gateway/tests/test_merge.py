from app.core.redaction.merge import merge_spans
from app.core.redaction.spans import SOURCE_PRESIDIO, SOURCE_REGEX, Span


def test_overlapping_spans_deduplicated():
    spans = [
        Span(0, 16, "PERSON", 0.6, SOURCE_PRESIDIO),
        Span(0, 16, "API_KEY", 1.0, SOURCE_REGEX),
    ]

    merged = merge_spans(spans)

    assert len(merged) == 1
    assert merged[0].entity_type == "API_KEY"


def test_non_overlapping_spans_both_kept():
    spans = [
        Span(0, 5, "PERSON", 0.6, SOURCE_PRESIDIO),
        Span(10, 20, "EMAIL_ADDRESS", 1.0, SOURCE_PRESIDIO),
    ]

    merged = merge_spans(spans)

    assert len(merged) == 2


def test_partial_overlap_keeps_higher_presidio_score():
    """Both spans are genuine Presidio results (same source) - here, and
    only here, comparing `score` directly is comparing like with like.
    """
    spans = [
        Span(0, 10, "PHONE_NUMBER", 0.4, SOURCE_PRESIDIO),
        Span(5, 15, "US_SSN", 0.9, SOURCE_PRESIDIO),
    ]

    merged = merge_spans(spans)

    assert len(merged) == 1
    assert merged[0].entity_type == "US_SSN"


def test_regex_wins_on_exact_format_entity_even_at_equal_score():
    """Regression test for the bug found in the module-4 audit: Presidio's
    own built-in CREDIT_CARD recognizer can also report score 1.0 for a real
    card number, tying the regex layer's hardcoded 1.0 and falling through
    to an arbitrary width/position tiebreak instead of a documented rule.
    A regex match on one of REGEX_EXACT_FORMAT_ENTITIES must win regardless
    of score - deliberately overlapping input, same entity type, tied score,
    Presidio's span wider (so a naive width tiebreak would have picked it).
    """
    presidio_guess = Span(0, 19, "CREDIT_CARD", 1.0, SOURCE_PRESIDIO)  # wider
    regex_match = Span(0, 16, "CREDIT_CARD", 1.0, SOURCE_REGEX)  # narrower

    merged = merge_spans([presidio_guess, regex_match])

    assert merged == [regex_match]


def test_regex_wins_on_exact_format_entity_even_against_higher_presidio_score():
    """Same rule, but with Presidio scoring *higher* than the regex layer's
    fixed value - proves this is a source-based rule, not just a tiebreak
    that happens to favor regex when scores are equal.
    """
    presidio_guess = Span(0, 16, "API_KEY", 0.99, SOURCE_PRESIDIO)
    regex_match = Span(0, 16, "API_KEY", 1.0, SOURCE_REGEX)

    merged = merge_spans([presidio_guess, regex_match])

    assert merged == [regex_match]


def test_presidio_wins_on_non_exact_format_entity_regardless_of_a_hypothetical_regex_span():
    """The flip side of the rule: outside REGEX_EXACT_FORMAT_ENTITIES,
    there's no regex layer in practice, but the resolution logic itself must
    not special-case *any* regex span - only ones on the trusted entity
    types. A regex-sourced span on an entity type outside the trusted set
    falls back to plain score comparison like any other overlap.
    """
    presidio_match = Span(0, 10, "PERSON", 0.85, SOURCE_PRESIDIO)
    low_confidence_regex = Span(0, 10, "PERSON", 0.1, SOURCE_REGEX)

    merged = merge_spans([presidio_match, low_confidence_regex])

    assert merged == [presidio_match]
