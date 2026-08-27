# Module 8: Admin Dashboard (the actual "webapp")

**Depends on:** modules 1–7 for their admin APIs (build against mocked API responses first if the backend isn't fully ready — see task 1)
**This is the only genuinely webapp piece of the project.** The gateway itself is a headless proxy; this is what you'll click through live in front of faculty.

## 1. Purpose & scope

A Next.js web application that gives an admin visibility into and control over everything the gateway modules do: policies, live threat/cost data, audit logs, and the human-review queue for the bandit.

**In scope:** dashboard shell + auth, policy configuration screens, usage/cost charts, threat analytics, audit log viewer, review queue UI.
**Out of scope:** any business logic — this is a pure client of the admin REST APIs defined in modules 3–7. If you find yourself computing something here that the backend should compute, move it to the backend.

## 2. Screens to build

| Screen | Consumes | Key components |
|---|---|---|
| Login / API key entry | Module 2 auth | Simple gate — this is a student project demo, full SSO is out of scope |
| Overview / home | Module 3, 5, 6 stats endpoints | Summary cards: spend this period, requests blocked today, active threats |
| Cost & usage | Module 3 `GET /v1/admin/usage`, `/budget` | Recharts line/bar chart of spend by team/model over time, budget edit form |
| PII redaction policy | Module 4 `GET/PUT /redaction-policy` | Checkbox list of entity types, mode toggle (mask/tokenize) |
| Threat analytics | Module 5, 6 stats endpoints | Action distribution chart (allow/redact/block/escalate over time), bandit confidence trend |
| Review queue | Module 6 `GET /review-queue`, `POST /decide` | Table of pending items with prompt context (redacted!), attack/benign decision buttons |
| Audit log viewer | Module 7 `GET /logs`, `/verify`, `/export` | Filterable/paginated table, a "verify integrity" button that calls `/logs/verify` and shows the result prominently — good demo moment |

## 3. Tech stack

- Next.js (App Router), TypeScript
- Recharts for charts (already vetted for artifacts, works fine as a standalone dependency too)
- Fetch data via a thin typed API client (`lib/api-client.ts`) — one function per admin endpoint, so a backend contract change only touches one file
- Component library: keep it simple — plain Tailwind, no heavy UI kit needed for a demo-scale dashboard

## 4. API client contract

Write `lib/api-client.ts` with one typed function per endpoint from modules 3–7, e.g.:
```ts
export async function getUsage(teamId: string, from: string, to: string): Promise<UsageRecord[]>
export async function getReviewQueue(): Promise<ReviewQueueItem[]>
export async function submitReviewDecision(id: string, decision: "attack" | "benign"): Promise<void>
export async function verifyAuditLog(): Promise<{ valid: boolean; firstBrokenEntry: string | null }>
```
Types should mirror the Pydantic models from the gateway modules exactly — mismatches here are the most common source of confusing bugs in a split frontend/backend build, so keep a shared `types.ts` that's manually kept in sync (or generate it from the OpenAPI schema FastAPI exposes automatically at `/openapi.json`, which is worth doing once modules 3–7 stabilize).

## 5. Implementation tasks

1. [ ] Scaffold Next.js app in `dashboard/` (`npx create-next-app`), Tailwind configured
2. [ ] Write `lib/api-client.ts` and `lib/types.ts` — start against a mock server (`msw` or a small JSON fixture server) so frontend work isn't blocked on backend completion
3. [ ] Build the dashboard shell: nav sidebar, auth gate, layout
4. [ ] Build Overview screen with summary cards
5. [ ] Build Cost & Usage screen with charts + budget edit form
6. [ ] Build PII Redaction Policy screen
7. [ ] Build Threat Analytics screen
8. [ ] Build Review Queue screen with working decide-action buttons
9. [ ] Build Audit Log Viewer with filters + the integrity-verify button
10. [ ] Swap the mock API layer for the real gateway admin API once modules 3–7 are ready; re-test every screen against real data
11. [ ] Add `dashboard/Dockerfile` and add the service to root `docker-compose.yml`

## 6. Test plan

| Test | Type | What it verifies |
|---|---|---|
| Component tests (React Testing Library) per screen | Unit | each screen renders given mock API data, handles loading/error/empty states |
| `api-client.test.ts` | Unit | each client function correctly shapes its request and parses its response against the mock server |
| Cypress/Playwright: review queue flow | E2E | log in → open review queue → decide an item → item disappears from pending list |
| Cypress/Playwright: audit verify flow | E2E | click "verify integrity" → see a "valid" result against a known-good seeded log |
| Manual accessibility pass | Manual | keyboard navigation works, form fields have labels, color contrast is acceptable — worth doing once before the faculty demo, not a full audit |

## 7. Definition of done

- [ ] Every screen works end-to-end against the real gateway (not just mocks)
- [ ] Review queue and audit-verify demo flows both work live — these are your two best faculty-demo moments, rehearse them
- [ ] Component + API client tests pass
- [ ] At least one E2E test passes against a locally running full stack (`docker compose up` including dashboard)
