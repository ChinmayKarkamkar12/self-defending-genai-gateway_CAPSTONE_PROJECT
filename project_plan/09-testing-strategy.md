# Module 9: Cross-Cutting Testing Strategy

**Depends on:** all modules — this file is read once modules 1–8 exist, to fill gaps between their individual test plans
**Purpose:** each module file above already has its own per-module test plan; this file covers what falls *between* modules — full pipeline integration, security boundary tests, and CI.

## 1. Testing pyramid for this project

```
        /  E2E  \         A handful: full request through every real stage, dashboard flows
       / Integration \     Per-module pipeline integration (already in each module's file)
      /    Unit Tests  \   The bulk — already specified per module
```

Don't add a large new E2E suite here — each module file already has integration tests for its own slice. This file's job is the handful of tests that only make sense once *everything* is wired together, plus CI/coverage policy.

## 2. Full-pipeline integration tests (new, live here — not owned by any single module)

| Test | What it verifies |
|---|---|
| `test_full_pipeline.py::test_benign_request_end_to_end` | A clean, benign prompt with no PII passes through all 5 real stages (budget, threat, PII, provider call, output scan, audit log) and gets a normal response |
| `test_full_pipeline.py::test_injection_attempt_end_to_end` | A known injection-style prompt gets scored high by module 5, the bandit (module 6) takes a non-allow action, and the audit log (module 7) correctly records the whole chain of decisions |
| `test_full_pipeline.py::test_pii_bearing_request_end_to_end` | A prompt with an embedded email/SSN comes out redacted before hitting the mocked provider, and the audit log records only the redaction summary, never the raw value |
| `test_full_pipeline.py::test_over_budget_request_blocked_before_provider_call` | A request from a team already over budget never reaches the mocked provider at all — assert the provider mock was not called |
| `test_full_pipeline.py::test_fail_closed_when_classifier_unavailable` | With `FAIL_MODE=closed`, killing the threat classifier mid-test causes the next request to 503, not silently pass through unscored |

## 3. Security boundary tests (explicitly cross-cutting)

These deserve their own file (`tests/test_security_boundaries.py`) because they check properties that must hold *regardless* of which module produced the data:

- No raw PII appears in: audit logs, bandit `ThreatEvent.context_features`, application logs (grep test logs for fixture PII strings)
- API keys are never logged or returned in any response body
- Upstream provider keys never appear in any client-facing response or error message
- A revoked API key is rejected even mid-session (no caching that outlives revocation)

## 4. Coverage targets

Set these per module type, not one blanket number:
- Core pipeline logic (`app/core/`): aim high — this is the security-critical path
- API route handlers: cover happy path + documented error codes
- Training scripts (`training/`): not unit-tested in the traditional sense — covered by the offline evaluation reports (precision/recall/F1, bandit-vs-baseline comparison) instead

Don't chase 100% coverage as a vanity metric — the security boundary tests and full-pipeline tests above matter more than a coverage percentage, and that's worth saying explicitly in your report if faculty ask about testing rigor.

## 5. CI setup

Extend the CI skeleton from module 1:
1. [ ] `ruff check` on every push
2. [ ] `pytest` for the gateway (unit + integration), fail the build on any failure
3. [ ] Dashboard: `npm run lint` + component tests
4. [ ] A scheduled (not per-push) job that runs `evaluate.py` (module 5) and `evaluate_bandit.py` (module 6) and posts the numbers somewhere visible (even just a CI log is fine) — these are slow enough that running them per-push would slow down normal development
5. [ ] E2E tests run against a `docker compose up` full stack in CI, on merge to main only (not every push — they're slower)

## 6. What to explicitly skip testing (say so in your report, don't pretend otherwise)

- Load/performance testing beyond a rough sanity check — out of scope for a semester timeline at student-project scale; note in the report that this is documented future work, not a real gap you're hiding
- The adversarial red-team stretch goal (module 6, section 10) — if you don't get to it, it wasn't tested because it wasn't built, and that's fine to say plainly
- Multi-region/failover testing — not relevant at single-instance Docker Compose demo scale

## 7. Definition of done for this module

- [ ] All full-pipeline integration tests pass against real (not stubbed) stage implementations
- [ ] All security boundary tests pass
- [ ] CI runs the full suite on every push and blocks merge on failure
- [ ] Coverage report exists and is reviewed once, even if not enforced as a hard gate
