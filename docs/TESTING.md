# Testing strategy

How the Self-Defending GenAI Gateway is tested, what each layer proves, what
the cross-cutting tests found, and what is deliberately not tested. Written
for module 9 (`project_plan/09-testing-strategy.md`); numbers are from
2026-10-14.

## At a glance

| Layer | Where | Count | Runs |
|---|---|---|---|
| Gateway unit + integration (per module) | `gateway/tests/test_*.py` | 437 tests | every push |
| Full pipeline, every real stage | `gateway/tests/test_full_pipeline.py` | 7 tests × 2 backends | "Full checks" (needs the trained model) |
| Security boundaries, across all modules | `gateway/tests/test_security_boundaries.py` | 4 tests × 2 backends | every push |
| Dashboard unit + component | `dashboard/src/**/*.test.ts(x)` | 45 tests | every push |
| Dashboard browser (E2E) | `dashboard/e2e/*.spec.ts` | 16 tests | "Full checks", against the Docker stack |
| Offline model evaluations | `training/evaluate.py`, `training/evaluate_bandit.py` | 2 reports | "Full checks", weekly |

The 437 includes both backend variants of the two cross-cutting files, and
the real-model tests (`test_full_pipeline.py`, `test_classifier.py`), which
skip without the checkpoint. On this machine, with the checkpoint, Postgres
and Redis, all 437 pass and none skip.

## The two backends

Most module tests share one SQLite session and a fake Redis (`conftest.py`):
fast, and nothing to install. The module 9 tests run the gateway as it runs
in production instead - one database session per request, the audit writer
on its own connection, nothing overridden but the upstream provider - on both:

- **sqlite**: a SQLite file (WAL) and fakeredis. Always runs.
- **postgres**: a scratch Postgres database migrated with `alembic upgrade
  head` (the real triggers and column types) and a real Redis. Runs when
  `TEST_POSTGRES_DSN` and `TEST_REDIS_URL` are set, which per-push CI does.

`tests/pipeline_stack.py` builds both.

## Full-pipeline tests (plan §2)

One request through every real stage: the trained DeBERTa classifier,
Presidio, the bandit, the session agent at its production setting (`auto`),
Redis budgets, usage accounting and the hash-chained audit writer. Only the
AI provider is mocked, and the tests check what was sent to it.

| Test | What it proves |
|---|---|
| benign request | A normal question passes every stage unchanged, is scored benign by the real model, and leaves a linked record in every module (audit entry, threat event, usage record, session event); the chain verifies |
| injection attempt | The real model scores it > 0.9, the bandit blocks or escalates, the provider is never called, and the audit entry, threat event and session event agree with each other |
| PII-bearing request | The email and SSN are masked before the provider sees them, the rest of the prompt is intact, and neither value appears in any table, any Redis key or any log line at DEBUG |
| over budget | Real spend accrues until the budget runs out; the refused request never reaches the provider and is audited as `blocked_budget`, unscored |
| fail closed | The classifier disappears mid-run: the next request gets a 503, is not sent upstream, and is audited as a pipeline error |
| fail open (contrast) | With `FAIL_MODE=open` the same request goes through unscored, and the audit entry says so (`threat_score` empty). Pins down ADR-0001's trade-off |
| injection in a tool call | An attack replayed inside a tool call's arguments is refused, while the same conversation with a harmless query goes through (the control) |

## Security boundary tests (plan §3)

These plant distinctive values, send traffic that exercises every module, and
then search *everything* the gateway produced: every row of every table, every
Redis key, every log line at DEBUG, every response (chat and admin), and what
was sent upstream. The admin endpoints are taken from the OpenAPI schema, so a
new table, column, log line or endpoint is covered without anyone adding a
test for it.

| Test | Rule |
|---|---|
| no raw PII anywhere | Email, phone, card and SSN (and fragments of them) never appear, across allowed, spot-checked (review queue), blocked, tool-call, tokenize-mode, upstream-error and unknown-model requests |
| gateway API key | The client's key is never logged, stored (only its SHA-256), returned, or forwarded upstream; near-miss keys aren't echoed back |
| upstream provider keys | Never in a response, a log line, the database or Redis - including when the provider's error quotes the key, a non-JSON body echoes it, or a network error message contains it |
| revoked key | A key revoked mid-session is refused on the very next request (no cache outlives revocation) |

## What module 9 found (and what was done)

The cross-cutting tests found real problems the per-module tests couldn't see.

1. **PII in logs at DEBUG.** Presidio's own logger writes the text it
   analyses ("Context list is: …"), and its IBAN recognizer logs matched text
   even at ERROR. `LOG_LEVEL` is configurable, so `LOG_LEVEL=DEBUG` would have
   written raw PII to the gateway's logs. Fixed: Presidio's loggers are
   silenced (`app/core/redaction/analyzer.py`); its failures still arrive as
   exceptions, already wrapped without text.
2. **Upstream error text reached clients.** The 502 detail was the httpx
   exception's text, which can carry the upstream URL (an internal Ollama
   host) or anything an error path quoted. Fixed: clients get the gateway's
   own description - `provider returned HTTP 401`, `provider timed out`,
   `provider unreachable (ConnectError)` (`describe_http_error`).
3. **Tool call arguments skipped every check.** Text in
   `tool_calls[].function.arguments` reached the provider unredacted,
   unscored by the classifier, and unread by the output scan. Fixed in
   `app/core/messages.py`, the redaction stage, the output scan and the
   bandit's strip step.
4. **The first fix for 3 would have blocked most tool-calling apps.** Raw
   JSON scores as an attack (`{"query": "onboarding guide for new employees"}`
   0.979; the bare value 0.031). The classifier now scores only the string
   values. Code-like values still score high (SQL 0.976) - recorded as L9-2.
5. **Arguments couldn't be cut.** `redact_and_allow` cuts suspicious windows,
   but cutting inside arguments would break their JSON, so it would have
   passed an attack in a tool call. Now whatever stays in the arguments
   counts toward the re-check, and the request is blocked if it still scores
   as an attack.
6. **Still open (L9-1).** A message's `name`, the `user` field, tool
   definitions, `response_format` schemas and unknown fields are forwarded
   as sent. A probe confirmed all five reach the provider unredacted.

Also confirmed: the L5-2 false positives reproduce with the shipped model in
a fresh process ("hello" 0.805, "No results." 0.903). One new test first
passed for the wrong reason - a two-word tool result scored as an attack on
its own - and was rebuilt with a harmless control.

### How the new tests were checked

Each new test that guards a fix was run against the old code first and
confirmed to fail there (Presidio logging, upstream error text, tool call
redaction, scoring and output scan, the strip re-check, the full-pipeline
tool-call test). A test that passes on broken code proves nothing.

## Coverage (plan §4)

Line + branch coverage of `gateway/app/` with the full suite on Postgres +
Redis (`pytest --cov`, configured in `gateway/pyproject.toml`): **97%** of
3,491 statements and their branches. Per-push CI prints it.

| Area | Coverage | Notes |
|---|---|---|
| `app/core/pipeline.py`, `messages.py`, `context.py`, `auth.py`, `main.py` | 100% | the request path and startup/shutdown |
| `app/core/stages` | 97.6% | |
| `app/core/threat` | 97.4% | |
| `app/core/redaction` | 97.2% | |
| `app/core/defense` | 96.4% | remaining: rare guard branches in reward reversal |
| `app/core/providers` | 96.2% | |
| `app/core/audit` | 95.2% | remaining: `verify.py`'s command-line entry, writer retry timing |
| `app/core/governance` | 89.9% | remaining: `redis_client.py`, the production Redis connection (tests inject one) |
| `app/api` | 98.6% | |
| `app/db` | 98.1% | remaining: the production engine wiring |

Reviewed once, file by file. The gaps that mattered were closed in module 9:
the paths where something fails *after* the provider answered (now tested to
withhold the unchecked response), the app's startup/shutdown (now tested),
the "older feature layout" guard in the review queue, and the Ollama error
paths. What remains is production wiring that tests replace on purpose.
Coverage is not enforced as a gate: a percentage says which lines ran, not
whether a test would notice them changing, which is why the new tests were
checked against the old code instead.

Training scripts (`training/`) are not unit-tested. They are covered by their
evaluation reports (precision/recall/F1, bandit vs static thresholds), which
the "Full checks" workflow re-runs weekly.

## CI (plan §5)

**`.github/workflows/ci.yml`, every push:**

1. `ruff check` (gateway)
2. `pytest -rs --cov` (gateway) against Postgres and Redis service
   containers, so the Postgres variants run too. `-rs` lists every skipped
   test with its reason (the real-model files skip here).
3. Dashboard: `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`.

**`.github/workflows/full-checks.yml`, on push to `main`, Mondays 03:00 UTC,
and on demand:**

- **model**: downloads the shipped classifier and the held-out data from
  the private Hugging Face repo, runs the real-model tests on Postgres +
  Redis (and fails if any of them skipped), then `evaluate.py` on the locked
  950-row v2 test set and `evaluate_bandit.py --data v2`. The numbers go to
  the run's summary page and an `evaluation-results` artifact. Locally the
  classifier evaluation reproduces the shipped result (macro-F1 0.908, benign
  false-positive rate 3.1%), and the bandit evaluation is identical run to
  run.
- **e2e**: builds the Docker stack on a fresh database, sends a benign, an
  attack and an unknown-model request (no real provider key: all three are
  refused or fail upstream, and all are audited), creates a throwaway admin,
  and runs the 16 Playwright tests.

Both jobs need the repository secret `HF_TOKEN` (a read token for
`Chinmayyyyy/genai-gateway-classifier`). Without it they fail with a message
saying so, rather than skipping (L9-3).

## What is deliberately not tested (plan §6)

Said plainly, so none of it is mistaken for a hidden gap:

- **Load and performance** beyond the rough check in L2-2 (~9 req/s; 100
  concurrent requests complete). Documented future work (L9-4).
- **The adversarial red-team stretch goal** (module 6, §10). It wasn't
  built, so it wasn't tested (L9-5).
- **Multi-instance, failover, multi-region.** Not relevant to a
  single-instance Docker Compose deployment; the one multi-process property
  that matters - two audit writers not forking the chain - is tested
  (L9-6).
- **A real AI provider.** Every automated test mocks it; real calls were
  checked by hand through Ollama (module 7). CI must not spend money (L9-7).

## Running it

```bash
# Gateway: everything, both backends (Docker's Postgres and Redis)
cd gateway
TEST_POSTGRES_DSN=postgresql://postgres:postgres@localhost:5432/postgres \
TEST_REDIS_URL=redis://localhost:6379/15 \
.venv/Scripts/python.exe -m pytest -rs --cov

# Dashboard
cd dashboard
npm run lint && npm run typecheck && npm test
E2E_ADMIN_USER=... E2E_ADMIN_PASSWORD=... npm run test:e2e   # against docker compose up

# Offline evaluations (repo root, needs training/checkpoints/final and training/data)
gateway/.venv/Scripts/python.exe training/evaluate.py --test-file training/data/v2/test.jsonl
gateway/.venv/Scripts/python.exe training/evaluate_bandit.py --data v2
```
