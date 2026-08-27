# Module 3: Cost & Usage Governance

**Depends on:** Module 1 (repo), Module 2 (pipeline hook interface, `budget_check_stage` stub)
**Feeds into:** Module 7 (audit log records cost per request), Module 8 (dashboard shows spend charts)
**Can be built in parallel with:** Module 4, Module 5

## 1. Purpose & scope

Implement the `budget_check_stage` for real: per-API-key and per-team spend tracking, budget limits, and rate limiting, backed by Redis for speed.

**In scope:** token counting, cost calculation per provider/model, sliding-window budgets, token-bucket rate limiting, usage query API for the dashboard.
**Out of scope:** the dashboard UI itself (module 8) — this module only needs to expose the data via API.

## 2. Data model additions

```
UsageRecord   (Postgres — durable record for reporting/dashboard)
  id: uuid (pk)
  api_key_id: uuid (fk)
  team_id: uuid (fk)
  model: str
  tokens_in: int
  tokens_out: int
  cost_usd: numeric(10,6)
  timestamp: timestamp

BudgetPolicy  (Postgres — admin-configured)
  id: uuid (pk)
  team_id: uuid (fk)
  period: enum(daily, monthly)
  limit_usd: numeric(10,2)
  rate_limit_rps: int
```

Redis keys (ephemeral, fast path):
```
budget:{team_id}:{period_key}      -> running spend total (INCRBYFLOAT)
ratelimit:{api_key_id}             -> token bucket state
```

## 3. Cost calculation

Maintain a static pricing table (`app/core/governance/pricing.py`) mapping `model -> {input_per_million, output_per_million}` in USD, sourced from each provider's published pricing. Document that this table needs manual updates when providers change pricing — flag it as a known maintenance point, not something to over-engineer for a student project.

```python
def calculate_cost(model: str, tokens_in: int, tokens_out: int) -> Decimal: ...
```

## 4. Pipeline stage contract

`budget_check_stage.process(ctx)`:
1. Look up the team's active `BudgetPolicy`
2. Read current spend from Redis for the current period window
3. If `current_spend >= limit_usd` → return `BLOCK` with reason `"budget_exceeded"`
4. Check the rate limiter (token bucket) for this API key → if empty, return `BLOCK` with reason `"rate_limited"`
5. Otherwise → `ALLOW`, attach `ctx.metadata["budget_remaining"]` for the response headers

A **second** hook runs after the provider responds (add this as part of the pipeline's post-call step, not a pre-call stage): once actual `tokens_in`/`tokens_out` are known from the provider's response, compute real cost, write a `UsageRecord`, and increment the Redis counter. Pre-call, you only have an estimate (or nothing) — the authoritative accounting happens post-call.

## 5. API contract (admin endpoints, consumed by dashboard in module 8)

| Endpoint | Purpose |
|---|---|
| `GET /v1/admin/usage?team_id=&from=&to=` | usage records for charting |
| `GET /v1/admin/budget/{team_id}` | current budget policy + remaining spend |
| `PUT /v1/admin/budget/{team_id}` | update budget policy |

## 6. Implementation tasks

1. [ ] Add `UsageRecord` and `BudgetPolicy` models + migration
2. [ ] Write `pricing.py` with a pricing table for at least GPT-4o-class and Claude Sonnet-class models
3. [ ] Write `app/core/governance/token_counter.py` using `tiktoken` for OpenAI models; use provider-reported usage where available for others
4. [ ] Write the real `budget_check_stage` replacing the module-2 stub
5. [ ] Write `app/core/governance/rate_limiter.py` implementing token-bucket in Redis (use a Lua script or `redis-py`'s atomic ops to avoid race conditions)
6. [ ] Wire the post-call cost-recording step into `app/core/pipeline.py`
7. [ ] Write the three admin endpoints above
8. [ ] Add Redis + Postgres services to `docker-compose.yml` if not already present from module 1

## 7. Test plan

| Test | Type | What it verifies |
|---|---|---|
| `test_pricing.py::test_calculate_cost_known_model` | Unit | cost math is correct for a known model/token count |
| `test_token_counter.py::test_tiktoken_count_matches_expected` | Unit | token counting matches `tiktoken`'s own reference count for a fixed string |
| `test_budget_stage.py::test_blocks_when_over_budget` | Unit | stage returns BLOCK when Redis spend ≥ limit |
| `test_budget_stage.py::test_allows_when_under_budget` | Unit | stage returns ALLOW and attaches remaining budget |
| `test_rate_limiter.py::test_token_bucket_refills_over_time` | Unit | bucket denies rapid-fire requests then allows again after the refill window |
| `test_rate_limiter.py::test_concurrent_requests_dont_double_spend` | Integration | fire N concurrent requests against a bucket sized for N-1, exactly one is rejected — this is the race-condition check, don't skip it |
| `test_usage_recording.py::test_post_call_writes_usage_record` | Integration | after a full pipeline run through a mocked provider, a `UsageRecord` row exists with correct cost |
| `test_admin_usage_api.py::test_usage_query_filters_by_team_and_date` | Integration | admin usage endpoint returns correctly filtered results |

## 8. Definition of done

- [ ] A team can be given a budget, spend against it, and get blocked once exceeded — verified end-to-end, not just unit-tested
- [ ] Rate limiting survives the concurrency test
- [ ] Admin usage endpoints return real data from a seeded scenario
- [ ] All tests pass; `ruff check` clean
