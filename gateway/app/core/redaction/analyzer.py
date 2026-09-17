"""Presidio analyzer wrapper, combined with the custom regex layer. See
project_plan/04-pii-redaction.md §3.

Uses spaCy's `en_core_web_sm` model rather than the default `en_core_web_lg`
(see project_plan/04-pii-redaction.md §5: "the smaller en_core_web_sm if
resources are tight for the demo environment") and builds the engine lazily
so importing this module doesn't pay spaCy's load cost until redaction is
actually needed.
"""
from functools import lru_cache

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from app.core.redaction import patterns
from app.core.redaction.merge import merge_spans
from app.core.redaction.spans import Span

_SPACY_MODEL = "en_core_web_sm"


@lru_cache(maxsize=1)
def get_analyzer_engine() -> AnalyzerEngine:
    config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": _SPACY_MODEL}],
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=config).create_engine()
    return AnalyzerEngine(nlp_engine=nlp_engine)


def analyze_text(text: str, enabled_entities: list[str]) -> list[Span]:
    """Detect PII spans in `text`, restricted to `enabled_entities`, merging
    Presidio's results with the custom regex layer's and de-duplicating
    overlaps. Entity types the custom layer alone knows about (API_KEY,
    CREDIT_CARD) are only run when they're in `enabled_entities`, same as
    Presidio's.
    """
    if not enabled_entities:
        return []

    engine = get_analyzer_engine()
    presidio_entities = [e for e in enabled_entities if e not in ("API_KEY",)]
    presidio_results = (
        engine.analyze(text=text, language="en", entities=presidio_entities)
        if presidio_entities
        else []
    )
    presidio_spans = [
        Span(r.start, r.end, r.entity_type, r.score) for r in presidio_results
    ]

    custom_spans = [s for s in patterns.detect_custom(text) if s.entity_type in enabled_entities]

    return merge_spans(presidio_spans + custom_spans)
