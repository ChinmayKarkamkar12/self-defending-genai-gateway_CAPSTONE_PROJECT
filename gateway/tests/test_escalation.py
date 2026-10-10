import pytest

from app.core.defense.escalation import (
    escalation_bias_key,
    parse_bias,
    read_escalation_bias,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, 0.0),
        ("0.4", 0.4),
        ("-0.25", -0.25),
        ("7", 1.0),
        ("-9", -0.3),
        ("-1", -0.3),
        ("nan", 0.0),
        ("inf", 0.0),
        ("not-a-number", 0.0),
        (b"0.5", 0.5),
    ],
)
def test_parse_bias(raw, expected):
    assert parse_bias(raw) == expected


async def test_reads_session_key(fake_redis):
    await fake_redis.set(escalation_bias_key("s-1"), "0.75")
    assert await read_escalation_bias(fake_redis, "s-1") == 0.75
    assert await read_escalation_bias(fake_redis, "s-2") == 0.0
    assert await read_escalation_bias(fake_redis, None) == 0.0
