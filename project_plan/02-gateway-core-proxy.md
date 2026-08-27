# Module 2: Gateway Core — Reverse Proxy & Provider Routing

**Depends on:** Module 1 (repo skeleton)
**Feeds into:** modules 3, 4, 5, 6, 7 all plug into the pipeline this module defines

## 1. Purpose & scope

Build the core request pipeline: an OpenAI-compatible endpoint that authenticates the caller, routes to the correct upstream LLM provider, and defines the **pipeline hook structure** that later modules (cost governance, PII redaction, threat detection) will plug into. This module ships with the pipeline hooks as no-op pass-throughs — later modules implement the actual logic.

**In scope:** auth, provider adapter pattern, request/response pass-through, pipeline hook interface, fail-open/fail-closed handling.
**Out of scope:** the actual detection/redaction/governance logic (modules 3–6) — only the interface they'll implement.

## 2. Data model additions (Postgres, via `gateway/app/db/`)

```
ApiKey
  id: uuid (pk)
  key_hash: str (never store raw keys)
  team_id: uuid
  name: str
  created_at: timestamp
  revoked: bool

Team
  id: uuid (pk)
  name: str
```

## 3. API contract

### `POST /v1/chat/completions`
OpenAI-compatible shape. Gateway accepts the same body OpenAI's SDK sends, forwards to the configured provider, returns the same shape back.

Request header: `Authorization: Bearer <gateway_api_key>` — this is a **gateway-issued** key, mapped internally to the real upstream provider key. The upstream key is never sent to or seen by the client.

Response: pass-through of the provider's response, plus an `x-gateway-request-id` header for correlating with audit logs later.

Error responses (define these now, even though nothing triggers them yet):
| Status | Meaning |
|---|---|
| 401 | invalid/revoked gateway API key |
| 402 | budget exceeded (module 3 will trigger this) |
| 422 | blocked by threat detection (module 5 will trigger this) |
| 502 | upstream provider error |
| 503 | a required pipeline component is down and `FAIL_MODE=closed` |

## 4. Pipeline hook interface (the key architectural piece)

Define an abstract pipeline stage interface that every later module implements:

```python
class PipelineStage(Protocol):
    async def process(self, ctx: RequestContext) -> StageResult:
        """Return ALLOW, BLOCK, or MODIFY(new_payload)."""
```

`RequestContext` carries: raw request body, api_key, team_id, a mutable `metadata` dict for stages to attach scores/flags to (threat score, redaction map, etc.), so later stages and the audit logger can read what earlier stages decided.

The main handler runs stages in a fixed order defined in `app/core/pipeline.py`:
```
[budget_check_stage, threat_detection_stage, pii_redaction_stage] -> provider_call -> [output_scan_stage] -> [audit_log_stage]
```
For this module, `budget_check_stage`, `threat_detection_stage`, `pii_redaction_stage`, `output_scan_stage`, and `audit_log_stage` are all no-op stubs that return `ALLOW` unconditionally. Modules 3–7 replace the stubs one at a time — the pipeline wiring doesn't change.

## 5. Provider adapter pattern

```
app/core/providers/
  base.py       # abstract Provider.chat_completion(payload) -> response
  openai.py     # concrete OpenAI implementation
  anthropic.py  # concrete Anthropic implementation
  registry.py   # maps a `model` string prefix to the right provider
```
This keeps adding a third provider later to a single new file, not a scattered change.

## 6. Fail-open vs fail-closed

Implement this now even though no stage can fail yet, because it's structural: wrap each pipeline stage call in a try/except. On an exception:
- if `FAIL_MODE=closed` (default) → return 503, don't forward to the provider
- if `FAIL_MODE=open` → log a warning, treat the stage as ALLOW, continue

This is the ADR-worthy decision from the architecture discussion — document the reasoning in a `docs/adr/0001-fail-open-vs-closed.md` file using the ADR format (Context / Decision / Options / Trade-offs / Consequences).

## 7. Implementation tasks

1. [ ] Add `ApiKey` and `Team` models + a migration (use `alembic`)
2. [ ] Write `app/core/context.py` — `RequestContext` and `StageResult` types
3. [ ] Write `app/core/pipeline.py` — the fixed-order stage runner with fail-open/closed handling
4. [ ] Write the five no-op stage stubs in `app/core/stages/` (one file each, so modules 3–7 each own one file)
5. [ ] Write `app/core/providers/base.py`, `openai.py`, `anthropic.py`, `registry.py`
6. [ ] Write `app/api/chat.py` — the `POST /v1/chat/completions` route wiring auth → pipeline → provider → response
7. [ ] Write `app/core/auth.py` — API key lookup/validation against the `ApiKey` table (hash comparison, never compare raw keys)
8. [ ] Write `docs/adr/0001-fail-open-vs-closed.md`
9. [ ] Seed script: create one test `Team` and `ApiKey` for local development

## 8. Test plan

| Test | Type | What it verifies |
|---|---|---|
| `test_auth.py::test_valid_key_passes` | Unit | valid API key resolves to correct team |
| `test_auth.py::test_invalid_key_rejected` | Unit | unknown/revoked key returns 401 |
| `test_pipeline.py::test_stages_run_in_order` | Unit | stages execute in the defined order, each receiving the mutated context from the previous |
| `test_pipeline.py::test_fail_closed_blocks_on_stage_error` | Unit | a stage raising an exception with `FAIL_MODE=closed` returns 503 and does not call the provider |
| `test_pipeline.py::test_fail_open_passes_on_stage_error` | Unit | same scenario with `FAIL_MODE=open` calls the provider anyway |
| `test_providers.py::test_registry_routes_by_model_prefix` | Unit | `gpt-*` routes to OpenAI adapter, `claude-*` routes to Anthropic adapter |
| `test_chat_endpoint.py::test_end_to_end_with_mocked_provider` | Integration | full request through auth → pipeline (no-ops) → mocked provider → response, using `respx` or similar to mock the upstream HTTP call |

## 9. Definition of done

- [ ] A request with a valid seeded API key round-trips through to a mocked provider and back
- [ ] Fail-open/fail-closed behavior is verified by test, not just by inspection
- [ ] ADR-0001 is written
- [ ] All tests above pass; `ruff check` clean
