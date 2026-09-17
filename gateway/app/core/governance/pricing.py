"""Static per-model pricing table and cost calculation.

Prices are USD per 1,000,000 tokens, sourced from each provider's published
pricing at the time this was written. This table needs manual updates
whenever a provider changes pricing or a new model is added — that's a known
maintenance point, not something worth over-engineering (e.g. a live pricing
API) for a student project.

See project_plan/03-cost-usage-governance.md §3.
"""
from decimal import Decimal

# model prefix -> {input_per_million, output_per_million} in USD
PRICING_TABLE: dict[str, dict[str, Decimal]] = {
    "gpt-4o": {
        "input_per_million": Decimal("2.50"),
        "output_per_million": Decimal("10.00"),
    },
    "gpt-4o-mini": {
        "input_per_million": Decimal("0.15"),
        "output_per_million": Decimal("0.60"),
    },
    "gpt-4": {
        "input_per_million": Decimal("30.00"),
        "output_per_million": Decimal("60.00"),
    },
    "claude-3-5-sonnet": {
        "input_per_million": Decimal("3.00"),
        "output_per_million": Decimal("15.00"),
    },
    "claude-3-opus": {
        "input_per_million": Decimal("15.00"),
        "output_per_million": Decimal("75.00"),
    },
    "claude-3-haiku": {
        "input_per_million": Decimal("0.25"),
        "output_per_million": Decimal("1.25"),
    },
}

_ONE_MILLION = Decimal("1000000")


class UnknownPricingError(Exception):
    """Raised when no pricing entry matches the given model."""


def _lookup(model: str) -> dict[str, Decimal]:
    # longest-prefix match so e.g. "gpt-4o-mini" doesn't match the "gpt-4o" entry
    matches = [prefix for prefix in PRICING_TABLE if model.startswith(prefix)]
    if not matches:
        raise UnknownPricingError(f"no pricing entry for model '{model}'")
    best = max(matches, key=len)
    return PRICING_TABLE[best]


def calculate_cost(model: str, tokens_in: int, tokens_out: int) -> Decimal:
    """Return the USD cost of a request as a Decimal, rounded to 6 places."""
    prices = _lookup(model)
    cost = (Decimal(tokens_in) / _ONE_MILLION * prices["input_per_million"]) + (
        Decimal(tokens_out) / _ONE_MILLION * prices["output_per_million"]
    )
    return cost.quantize(Decimal("0.000001"))
