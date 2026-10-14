# Self-Defending GenAI Gateway

A capstone project: a self-defending API gateway that sits in front of LLM
providers (OpenAI, Anthropic) and adds cost/usage governance, PII redaction,
threat detection, and adaptive defense — with full audit logging and an
admin dashboard.

See [`project_plan/`](project_plan/00-INDEX.md) for the full module-by-module
build plan.

## Quick start (5 minutes)

1. **Clone the repo**

   ```bash
   git clone https://github.com/ChinmayKarkamkar12/self-defending-genai-gateway_CAPSTONE_PROJECT.git
   cd self-defending-genai-gateway_CAPSTONE_PROJECT
   ```

2. **Configure environment**

   ```bash
   cp .env.example .env
   # then edit .env and fill in OPENAI_API_KEY / ANTHROPIC_API_KEY etc.
   ```

3. **Start the gateway**

   ```bash
   docker compose up
   ```

4. **Check it's alive**

   ```bash
   curl http://localhost:8000/health
   # -> {"status": "ok"}
   ```

## Repo layout

```
gateway/        FastAPI app (proxy, config, tests)
dashboard/      admin dashboard (added in module 8)
project_plan/   module-by-module implementation plan
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

The real-Postgres audit-log tests (`tests/test_audit_postgres.py`) are skipped
unless a Postgres server is given; each one creates and drops its own scratch
database:

```bash
docker compose up -d postgres
TEST_POSTGRES_DSN=postgresql://postgres:postgres@localhost:5432/postgres pytest tests/test_audit_postgres.py
```

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
