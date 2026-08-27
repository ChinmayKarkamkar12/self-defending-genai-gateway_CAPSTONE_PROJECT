# Module 10: Deployment — Docker Compose Demo Environment

**Depends on:** all modules must exist for the full compose stack to be meaningful, but the compose file itself should be built incrementally starting in module 1
**Purpose:** a one-command environment faculty (or you, at 2am before the presentation) can bring up reliably.

## 1. Purpose & scope

Package the whole system — gateway, dashboard, Postgres, Redis — into a `docker-compose.yml` that starts cleanly, seeds itself with demo data, and is resettable.

**In scope:** compose file, seed/demo data script, environment configuration, a scripted demo scenario.
**Out of scope:** Kubernetes, multi-node deployment, autoscaling — mention these as "future work / how this would scale to production" in your report, don't build them.

## 2. Final `docker-compose.yml` shape

```yaml
services:
  postgres:
    image: postgres:16
    environment: [...]
    volumes: [pgdata:/var/lib/postgresql/data]
  redis:
    image: redis:7
  gateway:
    build: ./gateway
    depends_on: [postgres, redis]
    env_file: .env
    ports: ["8000:8000"]
  dashboard:
    build: ./dashboard
    depends_on: [gateway]
    ports: ["3000:3000"]
volumes:
  pgdata:
```

## 3. Seed/demo data script

Write `scripts/seed_demo.py` that, on a fresh stack, creates:
- 2–3 demo teams with different budget policies (one intentionally near its limit, for a live demo of the block behavior)
- Demo API keys for each
- A handful of pre-populated `AuditLogEntry` rows spanning benign, redacted, and blocked requests, so the dashboard isn't empty on first load
- A few pending `ReviewQueueItem`s so the review queue demo has something to click through immediately

## 4. Scripted demo scenario (write this down, rehearse it)

A short, repeatable sequence to run live for faculty:
1. Send a benign request through the gateway (curl or a small script) → show it succeeds, appears in the dashboard's audit log
2. Send a request containing fake PII → show the redacted version in the log, confirm the raw value never appears
3. Send a known injection-style prompt → show it gets flagged, the bandit's action, and (if escalated) resolve it live in the review queue
4. Send requests until a demo team's budget is exceeded → show the 402 response and the dashboard's budget bar
5. Run the audit-log tamper demo (module 7's `scripts/tamper_demo.py`) → show `verify()` catching it

## 5. Implementation tasks

1. [ ] Finalize `docker-compose.yml` with all four services (started incrementally in earlier modules, completed here)
2. [ ] Write `scripts/seed_demo.py`
3. [ ] Write `scripts/reset_demo.sh` — tears down volumes and re-seeds, for a clean state before the actual presentation
4. [ ] Document the exact demo scenario steps in `docs/DEMO_SCRIPT.md`
5. [ ] Do a full clean-machine test: clone the repo fresh on a different machine (or a clean VM), `docker compose up`, run the demo script end to end, with no manual fixes

## 6. Test plan

| Test | Type | What it verifies |
|---|---|---|
| Manual: clean-machine bring-up | Smoke | fresh clone → `docker compose up` → all services healthy, no manual steps needed |
| Manual: seed script idempotency | Smoke | running `seed_demo.py` twice doesn't create duplicate teams/keys or crash |
| Manual: full demo script dry run | Smoke | all 5 scenario steps work in sequence without errors, at least twice before the real presentation |

## 7. Definition of done

- [ ] `docker compose up` works on a clean machine with zero manual intervention beyond copying `.env.example`
- [ ] The demo script runs cleanly at least twice in dry runs before the real presentation
- [ ] `docs/DEMO_SCRIPT.md` exists and matches what you'll actually say/do
