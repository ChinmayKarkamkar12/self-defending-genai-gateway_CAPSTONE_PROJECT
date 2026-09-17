"""Application configuration, loaded from environment variables / .env file.

Nothing "smart" lives here — just the typed settings contract every other
module reads from. See project_plan/01-repo-and-conventions.md.
"""
from typing import Literal

from pydantic import ValidationError
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

    # Fernet key (urlsafe-base64, 32 bytes) encrypting RedactionVault values at
    # rest for tokenize-mode PII redaction. Generate with
    # `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
    # Never hardcoded, never logged.
    #
    # KNOWN LIMITATION: no key rotation. This is a single static key for the
    # whole vault's lifetime - rotating it would require re-encrypting every
    # existing RedactionVault row (or supporting multiple active key
    # versions), neither of which is implemented. Out of scope for this
    # project; if this ever needs to run somewhere real, build rotation
    # before relying on it.
    REDACTION_VAULT_KEY: str

    LOG_LEVEL: str = "INFO"


def _load_settings(**overrides) -> Settings:
    # pydantic's ValidationError.__str__ (and .errors()' "input" key) embeds
    # the *entire* raw input dict for context on every error, including
    # every other already-valid, correctly-typed secret (REDACTION_VAULT_KEY,
    # OPENAI_API_KEY, ANTHROPIC_API_KEY, ...) in plaintext - confirmed by
    # reproducing it: a single missing/invalid field's error message prints
    # every sibling field's raw value straight to stderr/container logs.
    # `SecretStr` does NOT prevent this - the leaked dict is pre-validation
    # raw input, not the validated field. So on failure, extract only the
    # *names* of the offending fields (`err["loc"]`), never
    # `err["input"]`/`str(exc)`/`repr(exc)`, and raise the replacement error
    # only after leaving this `except` block entirely - not via `raise ...
    # from None` inside it - because Python auto-attaches the exception
    # currently being handled to a new exception's `__context__` the moment
    # it's raised inside an `except` clause, regardless of the `from`
    # clause; `from None` only stops that from being *printed* by default,
    # it doesn't clear `__context__`, so anything that inspects it directly
    # (rather than going through default traceback formatting) would still
    # see the original ValidationError and its embedded secrets. Raising
    # outside the `except` block avoids the exception ever being attached in
    # the first place.
    error_message: str | None = None
    try:
        return Settings(**overrides)
    except ValidationError as exc:
        offending_fields = sorted({str(err["loc"][0]) for err in exc.errors()})
        error_message = (
            "invalid gateway configuration - check these environment "
            f"variables: {', '.join(offending_fields)}"
        )
    raise RuntimeError(error_message)


settings = _load_settings()
