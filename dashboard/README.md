# Gateway checkpoint (admin dashboard)

Module 8 of the Self-Defending GenAI Gateway. See the repo root README's
"Admin dashboard" section for what each screen does and how to run it.

- `src/lib/api-client.ts`, `src/lib/types.ts`: one typed function per gateway
  admin endpoint; types mirror the gateway's Pydantic models by hand.
- `src/app/api/`: the dashboard's own server routes. `auth/login|logout` keep
  the gateway session in an httpOnly cookie; `gw/[...path]` forwards to the
  gateway's `/v1/admin` with it.
- `src/proxy.ts`: sends visitors without a session to `/login`.
- `src/lib/vocabulary.ts`: plain-language names and the four decision colours
  (allowed, cleaned, held, refused) used on every screen.

Tests: `npm test` (Vitest + React Testing Library, the gateway mocked with
MSW) and `npm run test:e2e` (Playwright against the running Docker stack).
