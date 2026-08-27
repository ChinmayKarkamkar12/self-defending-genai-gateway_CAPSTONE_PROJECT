"""Shared pytest fixtures.

Sets dummy required env vars *before* any `app.*` module is imported, so
`Settings()` (which requires POSTGRES_DSN / REDIS_URL / API keys) can be
instantiated in CI and local runs without a real `.env` file present.
Real values always win if they're already set in the environment.
"""
import os

os.environ.setdefault("POSTGRES_DSN", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("OPENAI_API_KEY", "test-key")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")
