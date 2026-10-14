import { http, HttpResponse, type JsonBodyType } from "msw";
import { describe, expect, it } from "vitest";

import { GW, server } from "@/test/server";
import { OVERVIEW, REVIEW_ITEM, TEAM } from "@/test/fixtures";
import {
  ApiError,
  auditExportUrl,
  getAuditLogs,
  getOverview,
  getRedactionPolicy,
  getReviewQueue,
  login,
  putBudget,
  submitReviewDecision,
  unlockApiKey,
  verifyAuditLog,
} from "./api-client";

/** Captures the request a handler received. */
function capture(method: "get" | "post" | "put", path: string, reply: JsonBodyType = {}) {
  const seen: { url?: URL; body?: unknown; method?: string } = {};
  server.use(
    http[method](`${GW}/${path}`, async ({ request }) => {
      seen.url = new URL(request.url);
      seen.method = request.method;
      if (method !== "get") seen.body = await request.json().catch(() => undefined);
      return HttpResponse.json(reply);
    }),
  );
  return seen;
}

describe("api-client", () => {
  it("parses a typed response", async () => {
    const overview = await getOverview();
    expect(overview.route).toHaveLength(6);
    expect(overview.decisions.cleaned).toBe(OVERVIEW.decisions.cleaned);
  });

  it("sends window and team as query parameters, skipping empty ones", async () => {
    const seen = capture("get", "stats/overview", OVERVIEW);
    await getOverview("2026-10-14T00:00:00Z", undefined, TEAM.id);
    expect(seen.url?.searchParams.get("from")).toBe("2026-10-14T00:00:00Z");
    expect(seen.url?.searchParams.get("team_id")).toBe(TEAM.id);
    expect(seen.url?.searchParams.has("to")).toBe(false);
  });

  it("sends audit filters and the pagination cursor", async () => {
    const seen = capture("get", "logs", { entries: [], next_before_sequence: null });
    await getAuditLogs({ outcome: "blocked_threat", from: "2026-10-01T00:00:00Z" }, 40, 25);
    expect(Object.fromEntries(seen.url!.searchParams)).toEqual({
      outcome: "blocked_threat",
      from: "2026-10-01T00:00:00Z",
      before_sequence: "40",
      limit: "25",
    });
  });

  it("asks for pending review items by default", async () => {
    const seen = capture("get", "review-queue", [REVIEW_ITEM]);
    await getReviewQueue();
    expect(seen.url?.searchParams.get("status")).toBe("pending");
  });

  it("sends only the decision when deciding (the gateway records who decided)", async () => {
    const seen = capture("post", `review-queue/${REVIEW_ITEM.id}/decide`, {
      item: REVIEW_ITEM,
      reward_applied: 0.45,
      bandit_updated: true,
    });
    const result = await submitReviewDecision(REVIEW_ITEM.id, "attack");
    expect(seen.method).toBe("POST");
    expect(seen.body).toEqual({ decision: "attack" });
    expect(result.reward_applied).toBe(0.45);
  });

  it("puts a budget as JSON", async () => {
    const seen = capture("put", `budget/${TEAM.id}`, {});
    await putBudget(TEAM.id, { period: "daily", limit_usd: "25", rate_limit_rps: 3 });
    expect(seen.body).toEqual({ period: "daily", limit_usd: "25", rate_limit_rps: 3 });
  });

  it("posts an unlock with no body", async () => {
    const seen = capture("post", "sessions/unlock/abc", { api_key_id: "abc", was_locked: true });
    expect((await unlockApiKey("abc")).was_locked).toBe(true);
    expect(seen.body).toBeUndefined();
  });

  it("turns an error response into an ApiError carrying the gateway's message", async () => {
    server.use(
      http.get(`${GW}/redaction-policy/:team`, () =>
        HttpResponse.json({ detail: "no redaction policy configured for this team" }, { status: 404 }),
      ),
    );
    const error = await getRedactionPolicy(TEAM.id).catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(404);
    expect(error.message).toBe("no redaction policy configured for this team");
  });

  it("joins validation errors (422) into one message", async () => {
    server.use(
      http.get(`${GW}/logs/verify`, () =>
        HttpResponse.json({ detail: [{ msg: "first" }, { msg: "second" }] }, { status: 422 }),
      ),
    );
    await expect(verifyAuditLog()).rejects.toThrow("first; second");
  });

  it("logs in through the dashboard's own route, not the gateway", async () => {
    let body: unknown;
    server.use(
      http.post("http://localhost:3000/api/auth/login", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ username: "chinmay" });
      }),
    );
    expect(await login("chinmay", "pw")).toEqual({ username: "chinmay" });
    expect(body).toEqual({ username: "chinmay", password: "pw" });
  });

  it("builds a relative CSV export link with the filters", () => {
    expect(auditExportUrl({ outcome: "escalated" })).toBe("/api/gw/logs/export?outcome=escalated&format=csv");
  });
});
