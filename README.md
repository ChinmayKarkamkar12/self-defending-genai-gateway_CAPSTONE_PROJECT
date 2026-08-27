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

## Status

🚧 Module 1 (repo skeleton & conventions) complete. See
[`project_plan/11-build-roadmap.md`](project_plan/11-build-roadmap.md) for
what's next.
