# ADR-0001: Fail-open vs. fail-closed pipeline error handling

## Context

The gateway's request pipeline runs a fixed sequence of stages (budget check,
threat detection, PII redaction, output scan, audit logging) between the
client and the upstream LLM provider. Any of these stages can fail at
runtime — a downstream dependency (Redis, Postgres, a model server) can be
unreachable, slow, or return malformed data.

We need a single, predictable policy for what happens to the in-flight
request when a pipeline stage raises an exception, because from module 3
onward these stages implement real security/cost logic and a silent
pass-through on error would defeat their purpose.

## Decision

The gateway **fails closed by default**: if any pipeline stage raises an
exception, the request is blocked and the gateway returns `503`, without
forwarding the request to the upstream provider.

This is controlled by the `FAIL_MODE` environment variable:
- `FAIL_MODE=closed` (default) — a stage error blocks the request (503).
- `FAIL_MODE=open` — a stage error is logged as a warning and the stage is
  treated as `ALLOW`; the request proceeds.

`FAIL_MODE=open` exists as an explicit, opt-in escape hatch (e.g. for local
development without Redis/Postgres running) — it is never the default in
any deployed environment.

## Options considered

1. **Fail closed (chosen).** Block the request on any stage error.
2. **Fail open.** Treat a stage error as an implicit ALLOW and continue.
3. **Per-stage policy.** Let each stage declare its own fail-open/closed
   behavior (e.g. budget check fails open, threat detection fails closed).

Option 3 was rejected for this module: it adds configuration surface and
per-stage judgment calls before any stage has real logic to reason about.
A single global switch is simpler to reason about and to defend in the
project viva; per-stage overrides can be revisited once modules 3–7 exist
and we have evidence of which stages actually need to diverge.

## Trade-offs

- **Fail closed** protects against the failure mode this project exists to
  prevent — a broken PII/threat-detection component silently letting an
  unfiltered request through — at the cost of availability: a Redis or
  Postgres blip takes the whole gateway down for new requests.
- **Fail open** maximizes availability but means the exact components this
  project is built around (redaction, threat detection, budget enforcement)
  can be silently bypassed by simply causing them to error, which is a much
  worse failure mode for a *security* proxy than downtime.

## Consequences

- Every pipeline stage call is wrapped in a `try/except` in
  `app/core/pipeline.py`; an exception is normalized into a `StageFailure`
  under `FAIL_MODE=closed`.
- `POST /v1/chat/completions` translates a `StageFailure` into a `503`
  response and never calls the upstream provider in that case.
- Deployments must monitor for `503`s caused by stage failures as a
  first-class alert — under fail-closed, a broken dependency shows up as
  gateway downtime, not as silently-degraded security.
- `FAIL_MODE=open` must never be set in production; this is documented in
  `.env.example` and enforced by convention/review, not by code, in this
  module. A future module may add a startup check that refuses
  `FAIL_MODE=open` when `ENVIRONMENT != local`.
