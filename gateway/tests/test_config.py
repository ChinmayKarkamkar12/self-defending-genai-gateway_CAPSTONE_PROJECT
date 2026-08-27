import pytest
from pydantic import ValidationError

from app.config import Settings


def test_settings_load_from_env(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv("POSTGRES_DSN", "postgresql://u:p@host:5432/db")
    monkeypatch.setenv("REDIS_URL", "redis://host:6379/0")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anthropic-test")
    monkeypatch.setenv("FAIL_MODE", "open")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")

    settings = Settings(_env_file=None)

    assert settings.ENVIRONMENT == "staging"
    assert settings.POSTGRES_DSN == "postgresql://u:p@host:5432/db"
    assert settings.REDIS_URL == "redis://host:6379/0"
    assert settings.OPENAI_API_KEY == "sk-openai-test"
    assert settings.ANTHROPIC_API_KEY == "sk-anthropic-test"
    assert settings.FAIL_MODE == "open"
    assert settings.LOG_LEVEL == "DEBUG"


def test_settings_fails_loudly_when_required_field_missing(monkeypatch):
    monkeypatch.delenv("POSTGRES_DSN", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)
