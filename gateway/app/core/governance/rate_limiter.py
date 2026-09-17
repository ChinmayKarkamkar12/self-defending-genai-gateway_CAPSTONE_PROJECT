"""Token-bucket rate limiting backed by Redis.

The check-and-consume operation is a single Lua script so concurrent
requests against the same bucket can't race each other (Redis executes Lua
scripts atomically) - this is the race-condition guard called out in
project_plan/03-cost-usage-governance.md §6 task 5 / §7's concurrency test.

Bucket capacity == `rate_limit_rps` (burst size), refilling at
`rate_limit_rps` tokens/second. Each request consumes 1 token.
"""
import time

from redis.asyncio import Redis

_TOKEN_BUCKET_SCRIPT = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local bucket = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(bucket[1])
local ts = tonumber(bucket[2])

if tokens == nil then
    tokens = capacity
    ts = now
end

local delta = now - ts
if delta < 0 then
    delta = 0
end
tokens = math.min(capacity, tokens + delta * refill_rate)

local allowed = 0
if tokens >= 1 then
    allowed = 1
    tokens = tokens - 1
end

redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, 3600)

return allowed
"""


def _bucket_key(api_key_id: str) -> str:
    return f"ratelimit:{api_key_id}"


async def check_and_consume(redis: Redis, api_key_id: str, rate_limit_rps: int) -> bool:
    """Attempt to consume one token from the bucket for `api_key_id`.

    Returns True if allowed, False if the bucket is empty (rate limited).
    """
    allowed = await redis.eval(
        _TOKEN_BUCKET_SCRIPT,
        1,
        _bucket_key(api_key_id),
        rate_limit_rps,
        rate_limit_rps,
        time.time(),
    )
    return bool(allowed)
