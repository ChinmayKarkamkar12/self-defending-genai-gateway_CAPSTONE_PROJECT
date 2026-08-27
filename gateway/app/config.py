"""Application configuration, loaded from environment variables / .env file.

Nothing "smart" lives here — just the typed settings contract every other
module reads from. See project_plan/01-repo-and-conventions.md.
"""
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed, environment-driven configuration for the gateway."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    ENVIRONMENT: Literal["local", "staging", "demo"] = "local"

    POSTGRES_DSN: str
    REDIS_URL: str

    OPENAI_API_KEY: str
    ANTHROPIC_API_KEY: str

    # "closed" = fail safe (block) on internal error, "open" = fail permissive.
    # See module 2 for the rationale.
    FAIL_MODE: Literal["open", "closed"] = "closed"

    LOG_LEVEL: str = "INFO"


settings = Settings()
