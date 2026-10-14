// A stand-in for the dashboard's /api/gw/* forwarder (and the gateway behind
// it), answering with the fixtures. Tests override handlers per case.
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";

import {
  BANDIT_STATS,
  BUDGET,
  ENTITIES,
  OVERVIEW,
  POLICY,
  REVIEW_ITEM,
  REVIEW_ITEM_2,
  REVIEWED_ITEM,
  SESSIONS,
  SPEND,
  TEAM,
  OTHER_TEAM,
  TIMELINE,
  VERIFY_OK,
  auditEntry,
} from "./fixtures";

export const GW = "http://localhost:3000/api/gw";

export const handlers = [
  http.get(`${GW}/auth/me`, () => HttpResponse.json({ username: "chinmay" })),
  http.get(`${GW}/teams`, () => HttpResponse.json([TEAM, OTHER_TEAM])),
  http.get(`${GW}/stats/overview`, () => HttpResponse.json(OVERVIEW)),
  http.get(`${GW}/stats/timeline`, () => HttpResponse.json(TIMELINE)),
  http.get(`${GW}/stats/spend`, () => HttpResponse.json(SPEND)),
  http.get(`${GW}/review-queue`, ({ request }) => {
    const status = new URL(request.url).searchParams.get("status");
    return HttpResponse.json(status === "reviewed" ? [REVIEWED_ITEM] : [REVIEW_ITEM, REVIEW_ITEM_2]);
  }),
  http.post(`${GW}/review-queue/:id/decide`, async ({ request, params }) => {
    const body = (await request.json()) as { decision: string };
    return HttpResponse.json({
      item: { ...REVIEW_ITEM, id: params.id, status: "reviewed", decision: body.decision, reviewer: "chinmay" },
      reward_applied: body.decision === "attack" ? 0.45 : -0.1,
      bandit_updated: true,
    });
  }),
  http.get(`${GW}/logs`, () =>
    HttpResponse.json({ entries: [auditEntry(3), auditEntry(2, { outcome: "blocked_threat" })], next_before_sequence: 2 }),
  ),
  http.get(`${GW}/logs/verify`, () => HttpResponse.json(VERIFY_OK)),
  http.get(`${GW}/bandit/stats`, () => HttpResponse.json(BANDIT_STATS)),
  http.get(`${GW}/sessions`, () => HttpResponse.json(SESSIONS)),
  http.get(`${GW}/budget/:team`, () => HttpResponse.json(BUDGET)),
  http.put(`${GW}/budget/:team`, async ({ request }) => {
    const body = (await request.json()) as { limit_usd: string };
    return HttpResponse.json({ ...BUDGET, limit_usd: body.limit_usd });
  }),
  http.get(`${GW}/redaction-entities`, () => HttpResponse.json(ENTITIES)),
  http.get(`${GW}/redaction-policy/:team`, () => HttpResponse.json(POLICY)),
  http.put(`${GW}/redaction-policy/:team`, async ({ request }) => HttpResponse.json(await request.json())),
];

export const server = setupServer(...handlers);
