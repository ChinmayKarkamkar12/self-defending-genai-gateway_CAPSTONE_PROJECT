from decimal import Decimal

import pytest

from app.core.governance.pricing import UnknownPricingError, calculate_cost


def test_calculate_cost_known_model():
    # gpt-4o: $2.50/M input, $10.00/M output
    cost = calculate_cost("gpt-4o", tokens_in=1_000_000, tokens_out=1_000_000)
    assert cost == Decimal("12.50")


def test_calculate_cost_scales_with_tokens():
    cost = calculate_cost("gpt-4o-mini", tokens_in=500_000, tokens_out=0)
    assert cost == Decimal("0.075000")


def test_calculate_cost_prefers_longest_matching_prefix():
    mini_cost = calculate_cost("gpt-4o-mini", tokens_in=1_000_000, tokens_out=0)
    full_cost = calculate_cost("gpt-4o", tokens_in=1_000_000, tokens_out=0)
    assert mini_cost != full_cost
    assert mini_cost == Decimal("0.150000")


def test_calculate_cost_unknown_model_raises():
    with pytest.raises(UnknownPricingError):
        calculate_cost("some-unlisted-model", tokens_in=100, tokens_out=100)
