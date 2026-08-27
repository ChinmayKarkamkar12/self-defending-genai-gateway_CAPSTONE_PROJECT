# Module 1: Repo Skeleton & Shared Conventions

**Depends on:** none — this is the first thing to build
**Feeds into:** every other module

## 1. Purpose & scope

Set up the repository structure, environment configuration, and tooling that every later module builds on. Nothing "smart" happens here — no detection, no redaction — just the skeleton and plumbing.

**In scope:** repo layout, dependency management, config loading, Docker base setup, CI skeleton, health-check endpoint.
**Out of scope:** any actual gateway logic (that's module 2).

## 2. Repo layout to create

```
genai-gateway/
├── gateway/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py            # FastAPI app entrypoint
│   │   ├── config.py          # pydantic-settings config
│   │   ├── api/                # route modules go here (empty for now)
│   │   ├── core/                # pipeline modules go here (empty for now)
│   │   └── db/                  # models/migrations go here (empty for now)
│   ├── tests/
│   │   └── test_health.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── pyproject.toml          # ruff + pytest config
├── dashboard/                    # placeholder, filled in module 8
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

## 3. Config contract (`gateway/app/config.py`)

Define a `Settings` class (pydantic-settings `BaseSettings`) with at minimum these fields, all overridable via environment variables:

| Field | Type | Purpose |
|---|---|---|
| `ENVIRONMENT` | str | `local` / `staging` / `demo` |
| `POSTGRES_DSN` | str | connection string, used from module 3 onward |
| `REDIS_URL` | str | used from module 3 onward |
| `OPENAI_API_KEY` | str | upstream provider key, never exposed to clients |
| `ANTHROPIC_API_KEY` | str | upstream provider key |
| `FAIL_MODE` | Literal["open","closed"] | default `"closed"` — see module 2 for why |
| `LOG_LEVEL` | str | default `"INFO"` |

Write `.env.example` with every one of these keys present and empty/placeholder values. Never commit a real `.env`.

## 4. Implementation tasks

1. [ ] Initialize git repo, add `.gitignore` (Python + Node + `.env`)
2. [ ] Create the directory layout above
3. [ ] Write `gateway/app/config.py` with the `Settings` class and `.env.example`
4. [ ] Write `gateway/app/main.py` with a bare FastAPI app and one `GET /health` endpoint returning `{"status": "ok"}`
5. [ ] Write `gateway/requirements.txt`: `fastapi`, `uvicorn[standard]`, `pydantic-settings`, `pytest`, `pytest-asyncio`, `httpx`, `ruff`
6. [ ] Write `gateway/pyproject.toml` with `ruff` config (line length 100, standard rule set) and `pytest` config (`asyncio_mode = "auto"`)
7. [ ] Write `gateway/Dockerfile` — slim Python base image, install requirements, run `uvicorn app.main:app`
8. [ ] Write root `docker-compose.yml` with just the `gateway` service for now (Postgres/Redis get added in module 3)
9. [ ] Write root `README.md` with a 5-minute quick-start: clone, copy `.env.example` to `.env`, `docker compose up`, curl the health endpoint
10. [ ] Set up a minimal CI config (GitHub Actions) that runs `ruff check` and `pytest` on every push

## 5. Test plan

| Test | Type | What it verifies |
|---|---|---|
| `test_health.py::test_health_returns_ok` | Unit/integration (via `httpx.AsyncClient`) | `GET /health` returns 200 and `{"status": "ok"}` |
| `test_config.py::test_settings_load_from_env` | Unit | `Settings()` correctly reads values from environment variables, and fails loudly (raises) if a required field is missing |
| Manual | Smoke | `docker compose up` succeeds and the health endpoint responds from outside the container |

## 6. Definition of done

- [ ] `docker compose up` starts the gateway with no errors
- [ ] `GET /health` returns 200
- [ ] `pytest` passes with 2+ tests
- [ ] `ruff check` passes with zero errors
- [ ] CI is green on the initial commit
