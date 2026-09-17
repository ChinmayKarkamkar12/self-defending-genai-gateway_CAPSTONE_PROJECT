import pytest
from pydantic import ValidationError

from app.config import Settings, _load_settings


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


def test_load_settings_error_never_leaks_a_sibling_secret_value(monkeypatch):
    """Security-critical regression test: pydantic's own ValidationError
    embeds the *entire* raw input dict - including every other correctly
    configured secret in plaintext - when just one field is missing. Confirm
    a real, distinctive secret value set on REDACTION_VAULT_KEY never
    appears anywhere in the error `_load_settings()` raises, only field
    names.
    """
    secret_value = "THIS-EXACT-STRING-MUST-NEVER-APPEAR-IN-ANY-ERROR-abc123"
    monkeypatch.setenv("REDACTION_VAULT_KEY", secret_value)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anthropic-test")
    monkeypatch.delenv("POSTGRES_DSN", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        _load_settings(_env_file=None)

    error_text = str(exc_info.value)
    assert secret_value not in error_text
    assert "POSTGRES_DSN" in error_text
    assert "REDIS_URL" in error_text
    # The original ValidationError (which does embed the secret) must not
    # survive anywhere on the raised exception - not as `__cause__`, and not
    # as `__context__` either (merely suppressing __context__'s *display*
    # via `from None` isn't enough - see app/config.py's _load_settings
    # docstring comment for why).
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
