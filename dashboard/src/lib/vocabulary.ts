// Plain-language names for everything the gateway reports, so every screen
// says the same thing the same way. Colours live here too: a decision has
// one colour everywhere.

import type { AuditOutcome, Decision, DefenseAction, RouteStageKey, SessionAction } from "./types";

export const DECISIONS: Decision[] = ["allowed", "cleaned", "held", "refused", "failed"];

export const DECISION_META: Record<
  Decision,
  { label: string; meaning: string; fill: string; text: string; wash: string; hex: string }
> = {
  allowed: {
    label: "Allowed",
    meaning: "Answered unchanged",
    fill: "bg-allowed",
    text: "text-allowed-ink",
    wash: "bg-allowed-wash",
    hex: "#2f7d6b",
  },
  cleaned: {
    label: "Cleaned",
    meaning: "Answered after personal data or risky text was removed",
    fill: "bg-cleaned",
    text: "text-cleaned-ink",
    wash: "bg-cleaned-wash",
    hex: "#b7862b",
  },
  held: {
    label: "Held",
    meaning: "Stopped and sent to a person for review",
    fill: "bg-held",
    text: "text-held-ink",
    wash: "bg-held-wash",
    hex: "#5b4bb7",
  },
  refused: {
    label: "Refused",
    meaning: "Stopped by a check",
    fill: "bg-refused",
    text: "text-refused-ink",
    wash: "bg-refused-wash",
    hex: "#a6243a",
  },
  failed: {
    label: "Failed",
    meaning: "An error, not a decision",
    fill: "bg-failed",
    text: "text-failed-ink",
    wash: "bg-failed-wash",
    hex: "#5d6878",
  },
};

// The bandit's four actions, in the decision they produce.
export const ACTION_DECISION: Record<DefenseAction, Decision> = {
  allow: "allowed",
  redact_and_allow: "cleaned",
  escalate_to_human: "held",
  block: "refused",
};

export const ACTION_LABEL: Record<DefenseAction, string> = {
  allow: "Allow",
  redact_and_allow: "Remove risky part",
  escalate_to_human: "Send to review",
  block: "Block",
};

export const OUTCOME_LABEL: Record<AuditOutcome, string> = {
  allowed: "Allowed",
  blocked_session_locked: "Key locked out",
  blocked_budget: "Over budget",
  blocked_rate_limit: "Too many requests",
  blocked_threat: "Blocked as an attack",
  escalated: "Sent to review",
  blocked_output_leak: "Reply leaked instructions",
  rejected_unknown_model: "Unknown model",
  rejected_streaming: "Streaming requested",
  upstream_error: "Provider error",
  pipeline_error: "Check unavailable",
  internal_error: "Internal error",
};

export const OUTCOME_DECISION: Record<AuditOutcome, Decision> = {
  allowed: "allowed",
  blocked_session_locked: "refused",
  blocked_budget: "refused",
  blocked_rate_limit: "refused",
  blocked_threat: "refused",
  escalated: "held",
  blocked_output_leak: "refused",
  rejected_unknown_model: "refused",
  rejected_streaming: "refused",
  upstream_error: "failed",
  pipeline_error: "failed",
  internal_error: "failed",
};

export const STAGE_META: Record<RouteStageKey, { label: string; stops: string }> = {
  intake: { label: "Intake", stops: "unsupported requests" },
  session: { label: "Session", stops: "locked-out keys" },
  budget: { label: "Budget", stops: "over budget or too fast" },
  screening: { label: "Screening", stops: "attacks, and holds doubtful ones" },
  provider: { label: "Provider", stops: "unknown models and provider errors" },
  output: { label: "Reply check", stops: "replies that leak instructions" },
};

export const SESSION_ACTION_LABEL: Record<SessionAction, string> = {
  maintain: "No change",
  tighten: "Tightened",
  relax: "Relaxed",
  challenge: "Challenged",
  lockout: "Locked out",
};

const ENTITY_LABEL: Record<string, string> = {
  EMAIL_ADDRESS: "Email addresses",
  PHONE_NUMBER: "Phone numbers",
  PERSON: "People's names",
  CREDIT_CARD: "Card numbers",
  US_SSN: "US social security numbers",
  API_KEY: "API keys and secrets",
  IP_ADDRESS: "IP addresses",
  LOCATION: "Places",
  IBAN_CODE: "Bank account numbers (IBAN)",
  US_PASSPORT: "US passport numbers",
  US_DRIVER_LICENSE: "US driver's licences",
  US_BANK_NUMBER: "US bank account numbers",
};

export function entityLabel(entity: string): string {
  return ENTITY_LABEL[entity] ?? entity.replaceAll("_", " ").toLowerCase();
}
