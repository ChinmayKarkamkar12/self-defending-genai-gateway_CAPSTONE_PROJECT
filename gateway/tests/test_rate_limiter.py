import asyncio

from app.core.governance import rate_limiter


async def test_token_bucket_refills_over_time(fake_redis, monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(rate_limiter.time, "time", lambda: clock["now"])

    # capacity 2, refills at 2 tokens/sec
    assert await rate_limiter.check_and_consume(fake_redis, "key-1", 2) is True
    assert await rate_limiter.check_and_consume(fake_redis, "key-1", 2) is True
    assert await rate_limiter.check_and_consume(fake_redis, "key-1", 2) is False

    clock["now"] += 1.0  # enough time for a full refill

    assert await rate_limiter.check_and_consume(fake_redis, "key-1", 2) is True


async def test_concurrent_requests_dont_double_spend(fake_redis):
    n = 10
    bucket_size = n - 1

    results = await asyncio.gather(
        *[
            rate_limiter.check_and_consume(fake_redis, "key-concurrent", bucket_size)
            for _ in range(n)
        ]
    )

    assert results.count(True) == bucket_size
    assert results.count(False) == 1
