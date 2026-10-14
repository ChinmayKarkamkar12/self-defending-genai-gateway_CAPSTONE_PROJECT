// One typed function per gateway admin endpoint (project_plan/08 §4).
// The browser never talks to the gateway directly: every call goes to this
// app's own /api/gw/* route, which attaches the admin session (kept in an
// httpOnly cookie the browser's JavaScript can't read) and forwards it.
// A gateway contract change should only ever touch this file and types.ts.

import type {
  AuditLogFilters,
  AuditLogPage,
  BanditStats,
  BudgetPolicy,
  BudgetPolicyIn,
  Me,
  Overview,
  RedactionEntities,
  RedactionPolicy,
  RedactionPolicyIn,
  ReviewDecisionResult,
  ReviewItem,
  ReviewStatus,
  RiskTrend,
  SessionSummary,
  Spend,
  Team,
  ThreatLabel,
  Timeline,
  UnlockResult,
  UUID,
  VerifyResult,
} from "./types";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type Query = Record<string, string | number | undefined | null>;

function origin(): string {
  return typeof window !== "undefined" ? window.location.origin : "http://localhost";
}

// A same-site path (no origin), so it renders identically on the server and
// in the browser and works as a link's href.
export function gatewayPath(path: string, query: Query = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  }
  const search = params.toString();
  return `/api/gw/${path.replace(/^\//, "")}${search ? `?${search}` : ""}`;
}

export function gatewayUrl(path: string, query: Query = {}): string {
  return new URL(gatewayPath(path, query), origin()).toString();
}

async function errorMessage(response: Response): Promise<string> {
  try {
    const body = await response.json();
    if (typeof body?.detail === "string") return body.detail;
    if (Array.isArray(body?.detail)) {
      return body.detail.map((d: { msg?: string }) => d.msg).filter(Boolean).join("; ");
    }
  } catch {
    // not JSON
  }
  return `request failed (${response.status})`;
}

async function request<T>(
  method: "GET" | "POST" | "PUT",
  url: string,
  body?: unknown,
): Promise<T> {
  const response = await fetch(url, {
    method,
    credentials: "same-origin",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });
  if (!response.ok) {
    throw new ApiError(response.status, await errorMessage(response));
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const get = <T>(path: string, query?: Query) => request<T>("GET", gatewayUrl(path, query));

// --- session (this app's own routes, not forwarded as-is) ---

export async function login(username: string, password: string): Promise<Me> {
  return request<Me>("POST", new URL("/api/auth/login", origin()).toString(), {
    username,
    password,
  });
}

export async function logout(): Promise<void> {
  await request<void>("POST", new URL("/api/auth/logout", origin()).toString());
}

export const getMe = () => get<Me>("auth/me");

// --- teams, stats (module 8) ---

export const getTeams = () => get<Team[]>("teams");

export const getOverview = (from?: string, to?: string, teamId?: UUID) =>
  get<Overview>("stats/overview", { from, to, team_id: teamId });

export const getTimeline = (from?: string, to?: string, bucket: "hour" | "day" = "hour") =>
  get<Timeline>("stats/timeline", { from, to, bucket });

export const getSpend = (from?: string, to?: string, teamId?: UUID) =>
  get<Spend>("stats/spend", { from, to, team_id: teamId, bucket: "day" });

// --- cost governance (module 3) ---

export const getBudget = (teamId: UUID) => get<BudgetPolicy>(`budget/${teamId}`);

export const putBudget = (teamId: UUID, body: BudgetPolicyIn) =>
  request<BudgetPolicy>("PUT", gatewayUrl(`budget/${teamId}`), body);

// --- PII redaction (module 4) ---

export const getRedactionEntities = () => get<RedactionEntities>("redaction-entities");

export const getRedactionPolicy = (teamId: UUID) =>
  get<RedactionPolicy>(`redaction-policy/${teamId}`);

export const putRedactionPolicy = (teamId: UUID, body: RedactionPolicyIn) =>
  request<RedactionPolicy>("PUT", gatewayUrl(`redaction-policy/${teamId}`), body);

// --- adaptive defense (modules 6a, 6b) ---

export const getReviewQueue = (status: ReviewStatus = "pending", limit = 50) =>
  get<ReviewItem[]>("review-queue", { status, limit });

export const submitReviewDecision = (id: UUID, decision: ThreatLabel) =>
  request<ReviewDecisionResult>("POST", gatewayUrl(`review-queue/${id}/decide`), { decision });

export const amendReviewDecision = (id: UUID, decision: ThreatLabel) =>
  request<ReviewDecisionResult>("POST", gatewayUrl(`review-queue/${id}/amend`), { decision });

export const getBanditStats = (from?: string, to?: string, bucket: "hour" | "day" = "day") =>
  get<BanditStats>("bandit/stats", { from, to, bucket });

export const getSessions = () => get<SessionSummary[]>("sessions");

export const getRiskTrend = (sessionId: string) =>
  get<RiskTrend>(`sessions/${encodeURIComponent(sessionId)}/risk-trend`);

export const unlockApiKey = (apiKeyId: UUID) =>
  request<UnlockResult>("POST", gatewayUrl(`sessions/unlock/${apiKeyId}`));

// --- audit log (module 7) ---

export const getAuditLogs = (filters: AuditLogFilters, beforeSequence?: number, limit = 50) =>
  get<AuditLogPage>("logs", { ...filters, before_sequence: beforeSequence, limit });

export const verifyAuditLog = () => get<VerifyResult>("logs/verify");

export const auditExportUrl = (filters: AuditLogFilters) =>
  gatewayPath("logs/export", { ...filters, format: "csv" });
