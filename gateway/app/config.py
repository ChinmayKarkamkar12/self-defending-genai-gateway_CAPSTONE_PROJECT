"""Application configuration, loaded from environment variables / .env file.

Nothing "smart" lives here — just the typed settings contract every other
module reads from. See project_plan/01-repo-and-conventions.md.
"""
from typing import Literal

from pydantic import Field, ValidationError
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

    # Override for where app/core/threat/classifier.py loads the trained
    # checkpoint from. Empty string (the default) means "use the repo-root
    # training/checkpoints/final/ path" - see classifier.py's
    # DEFAULT_CHECKPOINT_DIR. Set this in deployments that mount the
    # checkpoint somewhere else (project_plan/10-deployment-docker-compose.md).
    THREAT_MODEL_DIR: str = ""

    # Tactical bandit (project_plan/06a-adaptive-defense-bandit.md). See
    # app/core/defense/ for what each one does.
    # LinUCB exploration strength: how much an arm's uncertainty counts
    # toward its score. 0 = pure exploitation.
    BANDIT_ALPHA: float = Field(default=0.5, ge=0.0, le=5.0)
    # Safety mask: above this attack probability, `allow` is never an
    # option, however the learned policy (or exploration) scores it.
    BANDIT_ALLOW_MASK_THRESHOLD: float = Field(default=0.99, gt=0.0, le=1.0)
    # Same for `redact_and_allow`: a near-certain attack is blocked or
    # escalated, never stripped and passed on. Deliberately not lower: the
    # measured false positives sit at 0.95-0.995, and redacting them is how
    # the bandit recovers from that drift (0.95 here cut the drift result
    # in training/README.md from +0.139 to +0.029 reward/request).
    BANDIT_REDACT_MASK_THRESHOLD: float = Field(default=0.999, gt=0.0, le=1.0)
    # redact_and_allow strips every window whose attack probability is at
    # least this.
    BANDIT_REDACT_WINDOW_THRESHOLD: float = Field(default=0.5, gt=0.0, le=1.0)
    # ...but nothing is cut when no window reaches this: a near-benign
    # request the bandit chose to redact goes through unchanged.
    BANDIT_REDACT_MIN_WINDOW: float = Field(default=0.3, ge=0.0, le=1.0)
    # Forgetting: each update to an arm first multiplies its earlier real
    # feedback by this (effective memory ~1/(1-x) labels per arm). 1.0 =
    # never forget. The warm-start prior is never discounted.
    BANDIT_DISCOUNT: float = Field(default=0.999, gt=0.9, le=1.0)
    # Weight of the automatic label from a system-prompt leak, relative to
    # a human verdict (1.0). The leak check only ever produces attack labels
    # on allowed requests, so at full weight it skews learning one way.
    BANDIT_OUTPUT_SCAN_WEIGHT: float = Field(default=0.2, gt=0.0, le=1.0)
    # Review-queue flood protection: at most this many pending items per
    # team (further escalations become blocks and nothing more is queued),
    # and pending items expire, unlearned, after this many days.
    BANDIT_REVIEW_TEAM_CAP: int = Field(default=20, ge=1)
    BANDIT_REVIEW_TTL_DAYS: float = Field(default=7.0, gt=0.0)
    # Share of non-escalated decisions also queued for human review, so
    # allow/redact/block keep getting labelled feedback.
    BANDIT_SPOT_CHECK_RATE: float = Field(default=0.02, ge=0.0, le=1.0)

    # Session agent (project_plan/06b-adaptive-defense-rl-session-agent.md).
    # See app/core/defense/session.py and app/core/defense/rl/.
    # A session is one API key's requests until it goes this long without
    # one. The gateway can't see application users, so a shared key is one
    # session for all of them (LIMITATIONS.md L6b-1).
    SESSION_IDLE_SECONDS: int = Field(default=1800, ge=60)
    # Which session policy runs: "auto" (the trained DQN if the shipped
    # agent passed the go/no-go evaluation, the rule-based fallback
    # otherwise), "rule" (always the fallback), "dqn" (always the trained
    # agent) or "maintain" (session state is still tracked and logged, but
    # the bias is never changed). Switching needs no code change - see
    # rl/policy.py.
    SESSION_POLICY: Literal["auto", "rule", "dqn", "maintain"] = "auto"
    # The policy runs after every Nth request of a session, or after any
    # request arriving this many seconds after its last run.
    SESSION_POLICY_EVERY_N: int = Field(default=1, ge=1)
    SESSION_POLICY_EVERY_SECONDS: float = Field(default=60.0, gt=0.0)
    # How long a `lockout` refuses the API key's requests. An admin can
    # lift it earlier (POST /v1/admin/sessions/unlock/{api_key_id}).
    SESSION_LOCK_SECONDS: int = Field(default=900, ge=1)
    # Exported DQN weights (.npz), with its go/no-go verdict alongside
    # (same name, .json) for "auto". Empty = the files shipped with the
    # gateway, app/core/defense/rl/dqn_policy.npz / .json.
    SESSION_DQN_WEIGHTS: str = ""


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
