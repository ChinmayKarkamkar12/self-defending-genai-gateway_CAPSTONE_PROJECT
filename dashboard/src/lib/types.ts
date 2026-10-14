// Mirrors the gateway's Pydantic response models (gateway/app/api/*.py).
// Kept in sync by hand: when a gateway model changes, change it here too.
// Decimal fields arrive as strings (Pydantic serialises Decimal that way).

export type UUID = string;
export type ISODate = string;
export type DecimalString = string;

// app/db/models.py
export type AuditOutcome =
  | "allowed"
  | "blocked_session_locked"
  | "blocked_budget"
  | "blocked_rate_limit"
  | "blocked_threat"
  | "escalated"
  | "blocked_output_leak"
  | "rejected_unknown_model"
  | "rejected_streaming"
  | "upstream_error"
  | "pipeline_error"
  | "internal_error";

export type DefenseAction = "allow" | "redact_and_allow" | "block" | "escalate_to_human";
export type ThreatLabel = "attack" | "benign";
export type ReviewStatus = "pending" | "reviewed" | "expired";
export type ReviewReason = "escalation" | "spot_check" | "output_scan";
export type RewardSource = "human_review" | "output_scan";
export type SessionAction = "maintain" | "tighten" | "relax" | "challenge" | "lockout";
export type BudgetPeriod = "daily" | "monthly";
export type RedactionMode = "mask" | "tokenize";

// app/api/stats_admin.py
export type Decision = "allowed" | "cleaned" | "held" | "refused" | "failed";
export type RouteStageKey = "intake" | "session" | "budget" | "screening" | "provider" | "output";

export interface RouteStage {
  key: RouteStageKey;
  reached: number;
  stopped: number;
  cleaned: number;
}

export interface Overview {
  window_from: ISODate;
  window_to: ISODate;
  total_requests: number;
  answered: number;
  route: RouteStage[];
  decisions: Record<Decision, number>;
  outcomes: Record<AuditOutcome, number>;
  errors: number;
  spend_usd: DecimalString;
  tokens_in: number;
  tokens_out: number;
  pii_entities: Record<string, number>;
  pending_reviews: number;
}

export interface TimelineBucket {
  bucket_start: ISODate;
  decisions: Record<Decision, number>;
  total: number;
}

export interface Timeline {
  window_from: ISODate;
  window_to: ISODate;
  bucket: "hour" | "day";
  buckets: TimelineBucket[];
}

export interface SpendPoint {
  bucket_start: ISODate;
  team_id: UUID;
  model: string;
  requests: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd: DecimalString;
}

export interface Spend {
  window_from: ISODate;
  window_to: ISODate;
  bucket: "hour" | "day";
  points: SpendPoint[];
  total_usd: DecimalString;
}

// app/api/admin.py
export interface Team {
  id: UUID;
  name: string;
}

export interface BudgetPolicy {
  team_id: UUID;
  period: BudgetPeriod;
  limit_usd: DecimalString;
  rate_limit_rps: number;
  current_spend_usd: DecimalString;
  remaining_usd: DecimalString;
}

export interface BudgetPolicyIn {
  period: BudgetPeriod;
  limit_usd: string;
  rate_limit_rps: number;
}

export interface RedactionPolicy {
  team_id: UUID;
  enabled_entities: string[];
  mode: RedactionMode;
}

export interface RedactionPolicyIn {
  enabled_entities: string[];
  mode: RedactionMode;
}

export interface RedactionEntities {
  supported: string[];
  default_enabled: string[];
  default_mode: RedactionMode;
}

// app/api/defense_admin.py
export interface ReviewItem {
  id: UUID;
  threat_event_id: UUID;
  request_id: UUID;
  team_id: UUID;
  reason: ReviewReason;
  status: ReviewStatus;
  action_taken: DefenseAction;
  outcome: DefenseAction;
  threat_score: Record<string, number>;
  bandit_confidence: number;
  prompt_excerpt: string;
  created_at: ISODate;
  reviewer: string | null;
  decision: ThreatLabel | null;
  reviewed_at: ISODate | null;
  amendments: Record<string, unknown>[];
}

export interface ReviewDecisionResult {
  item: ReviewItem;
  reward_applied: number | null;
  bandit_updated: boolean;
}

export interface BanditTimelineBucket {
  bucket_start: ISODate;
  counts: Partial<Record<DefenseAction, number>>;
  total: number;
}

export interface RewardPoint {
  at: ISODate;
  reward: number;
  cumulative: number;
  source: RewardSource;
}

export interface BanditStats {
  window_from: ISODate;
  window_to: ISODate;
  model_version: number;
  updates_per_action: Partial<Record<DefenseAction, number>>;
  pending_reviews: number;
  action_counts: Partial<Record<DefenseAction, number>>;
  timeline: BanditTimelineBucket[];
  reward_trend: RewardPoint[];
  cumulative_reward: number;
  mean_reward: number | null;
}

// app/api/session_admin.py
export interface SessionSummary {
  session_id: string;
  team_id: UUID;
  api_key_id: UUID;
  first_at: ISODate;
  last_at: ISODate;
  policy_runs: number;
  last_action: SessionAction;
  last_bias: number;
}

export interface RiskRequestPoint {
  at: ISODate;
  attack_probability: number;
  action: DefenseAction;
  outcome: DefenseAction;
  escalation_bias: number;
  forced_escalation: boolean;
}

export interface RiskTrend {
  session_id: string;
  team_id: UUID;
  api_key_id: UUID;
  requests: RiskRequestPoint[];
  policy_runs: {
    at: ISODate;
    policy: string;
    action: SessionAction;
    bias_before: number;
    bias_after: number;
  }[];
  live: { active: boolean; escalation_bias: number; challenge_pending: boolean; locked: boolean };
}

export interface UnlockResult {
  api_key_id: UUID;
  was_locked: boolean;
}

// app/api/audit_admin.py
export interface AuditLogEntry {
  id: UUID;
  sequence_number: number;
  timestamp: ISODate;
  request_id: UUID;
  team_id: UUID;
  api_key_id: UUID;
  model: string;
  http_status: number;
  outcome: AuditOutcome;
  pipeline_stage: string | null;
  redaction_summary: Record<string, number>;
  threat_score: Record<string, number> | null;
  action_taken: string;
  threat_event_id: UUID | null;
  session_id: string | null;
  session_action: string | null;
  output_flags: { system_prompt_leaked: boolean; echoed_redaction_tokens: number } | null;
  tokens_in: number;
  tokens_out: number;
  cost_usd: DecimalString;
  latency_ms: number;
  prev_hash: string;
  entry_hash: string;
}

export interface AuditLogPage {
  entries: AuditLogEntry[];
  next_before_sequence: number | null;
}

export interface AuditLogFilters {
  team_id?: UUID;
  from?: ISODate;
  to?: ISODate;
  action?: string;
  outcome?: AuditOutcome;
}

export interface VerifyResult {
  valid: boolean;
  first_broken_entry: UUID | null;
  first_broken_sequence: number | null;
  reason: string | null;
  entry_count: number;
  head_hash: string;
}

// app/api/admin_auth.py (through the dashboard's own /api/auth routes)
export interface Me {
  username: string;
}
