# Build Progress

## Completed modules
- [x] Module 1: Repo & conventions — `docker compose up` works, `GET /health` returns 200, pytest (3 tests) and ruff both clean, CI added. Commit `8d185a2`.
  - Re-verified end-to-end on 2026-08-27: repo structure matches plan §2, `docker compose up -d` starts cleanly, `curl /health` → 200 `{"status":"ok"}`, `pytest` 3/3 pass, `ruff check .` clean, `.env` untracked & git-ignored, missing-`.env` fails loudly (compose error + pydantic ValidationError), CI green on GitHub Actions for commits `8d185a2` and `61f0c3f`. Every Definition-of-Done item confirmed.
- [x] Module 2: Gateway core proxy — `POST /v1/chat/completions` with auth, pipeline hook interface, provider adapters, fail-open/closed handling. Built on branch `module-2-gateway-core-proxy` (not yet merged/PR'd — see notes).
  - `ApiKey`/`Team` SQLAlchemy models + alembic migration `0001_initial_teams_api_keys`. Re-verified 2026-09-07 against a real Postgres (`docker compose up -d postgres redis`): migration applied cleanly, `\d api_keys` matches the model exactly, seed script created a real Team+ApiKey row, and the running gateway (uvicorn, real Postgres) correctly returned 401 for an invalid key and 502 for a valid key + fake upstream OpenAI key (auth + pipeline + provider routing all confirmed live, not just against SQLite).
  - `app/core/context.py` (RequestContext/StageResult/Decision), `app/core/pipeline.py` (fixed-order stage runner, fail-open/closed via `StageFailure`), 5 no-op stage stubs in `app/core/stages/`.
  - `app/core/providers/{base,openai,anthropic,registry}.py` — routes by model prefix (`gpt-*` / `claude-*`); Anthropic adapter translates OpenAI-shaped payload/response.
  - `app/core/auth.py` (SHA-256 key hash lookup), `app/api/chat.py` (auth → pipeline → provider → response, `x-gateway-request-id` header, 401/422/502/503 mapped).
  - `docs/adr/0001-fail-open-vs-closed.md` written.
  - `gateway/scripts/seed.py` seed script for local Team+ApiKey.
  - docker-compose.yml: added `postgres` (16-alpine) and `redis` (7-alpine) services (previously only the `gateway` service existed).
  - Tests: 16 passing (`test_auth.py`, `test_pipeline.py`, `test_providers.py`, `test_chat_endpoint.py`) — DB-dependent tests run against in-memory SQLite via a `get_db` dependency override, not live Postgres. `ruff check .` clean.

## In progress
(none yet)

## Not started
- [ ] Module 3: Cost & usage governance
- [ ] Module 4: PII redaction
- [ ] Module 5: Threat detection classifier
- [ ] Module 6a: Adaptive defense — tactical bandit
- [ ] Module 6b: Adaptive defense — RL session agent
- [ ] Module 7: Audit logging
- [ ] Module 8: Admin dashboard
- [ ] Module 9: Testing strategy
- [ ] Module 10: Deployment
- [ ] Module 11: Build roadmap (reference only, not implemented)

## Notes for next session
- Module 1 was committed and pushed directly to `main` (no feature branch/PR), which deviates from the CLAUDE.md convention of "one feature branch per module, PR per module." Starting with Module 2, work should go on a feature branch (e.g. `module-2-gateway-core-proxy`) with a PR, unless told otherwise.
- Docker smoke test verified manually: built image, ran container, curled `/health` from host, got `{"status":"ok"}`, then tore down with `docker compose down`.
- `.env` used for local testing was a copy of `.env.example` with placeholder (non-real) API keys — not committed.
- Module 2's live-Postgres gap is now closed — migration, seed script, and the running gateway were all verified against real `postgres`/`redis` containers on 2026-09-07.
- **Fixed a real bug found during that verification:** `docker-compose.yml`'s `gateway` service inherited `POSTGRES_DSN`/`REDIS_URL` from `.env`, which point at `localhost` — correct for host-run uvicorn/tests/alembic/seed script, but wrong inside the compose network, where `localhost` in the gateway container resolves to itself, not the `postgres`/`redis` containers. Fixed by adding a `gateway.environment` override in `docker-compose.yml` that points the containerized gateway at the `postgres`/`redis` service hostnames instead (env_file value is superseded by it); also added healthchecks + `depends_on: condition: service_healthy` for both so the gateway doesn't start racing a not-yet-ready DB.
- Re-verified with a full `docker compose up -d --build` (all three services, not just postgres/redis): image built cleanly, `settings.POSTGRES_DSN` inside the gateway container correctly resolved to `postgres:5432`, and the same 401/502 checks as before passed through the actual containerized gateway. Torn down with `docker compose down` afterward (Postgres data volume kept).
- Module 2 work is on branch `module-2-gateway-core-proxy`, not yet merged to `main` and no PR opened yet — do that (or ask whether to) before/when starting Module 3.
- New deps added to `gateway/requirements.txt`: `sqlalchemy`, `asyncpg`, `psycopg2-binary` (alembic sync driver), `alembic`, `aiosqlite` (test-only), `respx` (test-only).
- Test DB strategy: unit/integration tests use in-memory SQLite via `app.db.session.get_db` dependency override (see `gateway/tests/conftest.py`), not real Postgres — fast and hermetic, but means the ORM-to-Postgres mapping itself (as opposed to the migration DDL) is untested against real Postgres.
