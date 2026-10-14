# Self-Defending GenAI Gateway

A capstone project: a self-defending API gateway that sits in front of LLM
providers (OpenAI, Anthropic) and adds cost/usage governance, PII redaction,
threat detection, and adaptive defense — with full audit logging and an
admin dashboard.

See [`project_plan/`](project_plan/00-INDEX.md) for the full module-by-module
build plan.

## Quick start

Needs Docker Desktop, and the trained classifier at
`training/checkpoints/final/` (it isn't in git: copy the folder over, or put a
Hugging Face read token in `.env` as `HF_TOKEN` and it downloads on first
start). For models to actually answer without a paid key, run
[Ollama](https://ollama.com) with `ollama pull llama3`.

1. **Clone the repo**

   ```bash
   git clone https://github.com/ChinmayKarkamkar12/self-defending-genai-gateway_CAPSTONE_PROJECT.git
   cd self-defending-genai-gateway_CAPSTONE_PROJECT
   ```

2. **Start everything, seeded with demo data**

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\reset_demo.ps1   # Windows
   ./scripts/reset_demo.sh                                           # macOS / Linux
   ```

   It creates `.env` from `.env.example` with every secret generated, then
   builds and starts the stack: Postgres, Redis, the gateway and the
   dashboard. Database setup, the gateway's restricted database role, demo
   teams and keys, a dashboard admin and some real traffic all happen on
   their own. It prints the dashboard login when it's ready (~1.5 minutes).
   Run it again any time for a clean slate - it asks before deleting data.

   Without the script: `cp .env.example .env`, fill in the empty secrets it
   lists, then `docker compose up -d --build`.

3. **Use it**

   - Dashboard: http://localhost:3000
   - Gateway: http://localhost:8000 (`curl http://localhost:8000/health`)
   - The live demo, step by step: [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md)
   - Demo API keys, for your own requests:
     `docker compose exec gateway python -m scripts.demo keys`

**How it starts** (`docker-compose.yml`): `model` checks the classifier is in
place (downloading it if needed), `migrate` applies migrations and creates
the `gateway_app` role as the database owner, then the gateway starts with
only that restricted login (it can't disable the audit log's protection),
then the dashboard and the one-off demo traffic. Postgres and Redis listen
on 127.0.0.1 only.

## Repo layout

```
gateway/        FastAPI app (proxy, config, tests, scripts)
dashboard/      admin dashboard (Next.js, module 8)
project_plan/   module-by-module implementation plan
scripts/        reset_demo.ps1 / reset_demo.sh (module 10)
docs/           testing strategy, demo script, project journey, ADRs
docker-compose.yml
.env.example
```

## Development (without Docker)

```bash
cd gateway
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
cp ../.env.example .env      # fill in values; pydantic-settings reads gateway/.env
uvicorn app.main:app --reload
```

## Testing & linting

```bash
cd gateway
pytest
ruff check .
```

The real-Postgres audit-log tests and the Postgres + Redis variants of the
cross-cutting tests are skipped unless a Postgres server and a Redis database
are given. Each test creates and drops its own scratch database; the Redis
database is flushed, so use one nothing else uses (15 here):

```bash
docker compose up -d postgres redis
TEST_POSTGRES_DSN=postgresql://postgres:postgres@localhost:5432/postgres \
TEST_REDIS_URL=redis://localhost:6379/15 pytest -rs --cov
```

`tests/test_full_pipeline.py` needs the trained classifier at
`training/checkpoints/final/` and is skipped without it. The full testing
strategy, what each layer proves, the coverage review and what is deliberately
not tested are in [docs/TESTING.md](docs/TESTING.md).

## Audit log (module 7)

Every authenticated request gets one hash-chained entry in
`audit_log_entries`: what each module decided (cost, PII counts, threat
score, bandit action, session action, outcome), never prompt text or raw PII.

```bash
curl http://localhost:8000/v1/admin/logs                     # query (filters: team_id, from, to, action, outcome)
curl http://localhost:8000/v1/admin/logs/verify              # re-check the whole chain
curl "http://localhost:8000/v1/admin/logs/export?format=csv" # compliance export
docker compose exec gateway python -m scripts.tamper_demo --postgres   # tamper with one entry, watch verify catch it
```

**Scaling limitation, by design:** entries are queued in memory
(`asyncio.Queue`) and written by one background worker, so logging never
delays a response. A crash loses whatever is still queued (normally a few
milliseconds' worth). A production system would use a durable queue such as
Redis Streams or Kafka here. See [`LIMITATIONS.md`](LIMITATIONS.md) L7-1 to
L7-8 and [`docs/adr/0002-audit-log-immutability.md`](docs/adr/0002-audit-log-immutability.md).

## Admin dashboard (module 8)

http://localhost:3000, a Next.js app that is purely a client of the gateway's
`/v1/admin` API. Every admin route requires a signed-in admin (username +
password); the browser never sees the session token, which the dashboard's
own server keeps in an httpOnly cookie and attaches when it forwards calls.

| Screen | What it's for |
|---|---|
| Overview | The route through the checkpoint: how many requests each check stopped, decisions over time, spend, personal data removed, audit-log integrity |
| Review queue | Decide held requests as attack or safe (keys **A** / **S**); verdicts teach the defense |
| Audit log | Every request as a ledger with hash links; "Check integrity" re-hashes the whole chain; CSV export |
| Threats | What the per-request defense chose, whether it's learning, per-session risk and unlocking a locked-out key |
| Cost & usage | Budget gauge and limits per team, spend by model |
| Personal data | Which kinds of personal data each team removes, and how |

Live tamper demo: run
`docker compose exec gateway python -m scripts.tamper_demo --postgres --hold`,
click **Check integrity** on the Audit log screen (it names the edited entry),
then press Enter in the terminal to restore it.

Dashboard development and tests (Node 24):

```bash
cd dashboard
npm install
GATEWAY_URL=http://localhost:8000 npm run dev      # http://localhost:3000
npm run lint && npm run typecheck && npm test      # unit + component tests
E2E_ADMIN_USER=... E2E_ADMIN_PASSWORD=... npm run test:e2e   # against docker compose up
```

## Streaming is not supported

Requests with `"stream": true` get a 422 straight away (nothing is sent
upstream): the gateway checks the complete response, for system-prompt leaks
and echoed redaction tokens, before returning any of it. Send requests
without streaming. See [`LIMITATIONS.md`](LIMITATIONS.md) L2-3.

## Optional: run without a paid API key (Ollama)

The gateway can forward to a local [Ollama](https://ollama.com) server instead
of OpenAI/Anthropic. It's **off by default** and changes nothing else.

1. Install Ollama and pull a model: `ollama pull llama3`
2. Add to `.env`: `OLLAMA_BASE_URL=http://host.docker.internal:11434/v1`
   (`http://localhost:11434/v1` if the gateway runs on the host), then
   `docker compose up -d --build`
3. Ask for model `local-<name>`; the gateway forwards it as `<name>`:

```bash
curl http://localhost:8000/v1/chat/completions -H "Authorization: Bearer $KEY"   -H "Content-Type: application/json"   -d '{"model": "local-llama3:latest", "messages": [{"role": "user", "content": "hi"}]}'
```

Local models are priced at $0, so cost budgets never trip for them (rate
limits still apply). Remove the `.env` line to switch it off. The first
request after Ollama has been idle is slow (it loads the model into memory).

## Status

🚧 Modules 1–7 complete (through tamper-evident audit logging); the
dashboard (module 8) is next. See
[`PROGRESS.md`](PROGRESS.md) for module-by-module status,
[`LIMITATIONS.md`](LIMITATIONS.md) for known limitations, and
[`project_plan/11-build-roadmap.md`](project_plan/11-build-roadmap.md) for
what's next.
