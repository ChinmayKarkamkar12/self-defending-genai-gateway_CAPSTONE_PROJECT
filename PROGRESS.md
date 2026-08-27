# Build Progress

## Completed modules
- [x] Module 1: Repo & conventions — `docker compose up` works, `GET /health` returns 200, pytest (3 tests) and ruff both clean, CI added. Commit `8d185a2`.

## In progress
(none yet)

## Not started
- [ ] Module 2: Gateway core proxy
- [ ] Module 3: Cost & usage governance
- [ ] Module 4: PII redaction
- [ ] Module 5: Threat detection classifier
- [ ] Module 6a: Adaptive defense — tactical bandit
- [ ] Module 6b: Adaptive defense — RL session agent
- [ ] Module 7: Audit logging
- [ ] Module 8: Admin dashboard
- [ ] Module 9: Testing strategy
- [ ] Module 10: Deployment
- [ ] Module 11: Build roadmap (reference only, not implemented)

## Notes for next session
- Module 1 was committed and pushed directly to `main` (no feature branch/PR), which deviates from the CLAUDE.md convention of "one feature branch per module, PR per module." Starting with Module 2, work should go on a feature branch (e.g. `module-2-gateway-core-proxy`) with a PR, unless told otherwise.
- Docker smoke test verified manually: built image, ran container, curled `/health` from host, got `{"status":"ok"}`, then tore down with `docker compose down`.
- `.env` used for local testing was a copy of `.env.example` with placeholder (non-real) API keys — not committed.
