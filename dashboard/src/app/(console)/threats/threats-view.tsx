"use client";

import { useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { useTeams } from "@/components/team-picker";
import { Button, DecisionChip, PageHeader, Segmented, SectionTitle, Status } from "@/components/ui";
import {
  ApiError,
  getBanditStats,
  getRiskTrend,
  getSessions,
  unlockApiKey,
} from "@/lib/api-client";
import { count, dateTime, shortDate, windowRange, type WindowKey } from "@/lib/format";
import type { BanditStats, DefenseAction, RiskTrend } from "@/lib/types";
import { goToLogin, useGateway } from "@/lib/use-gateway";
import {
  ACTION_DECISION,
  ACTION_LABEL,
  DECISION_META,
  SESSION_ACTION_LABEL,
} from "@/lib/vocabulary";

const ACTIONS: DefenseAction[] = ["allow", "redact_and_allow", "escalate_to_human", "block"];
const AXIS = { fill: "#45566c", fontSize: 12 };

function ActionChart({ stats }: { stats: BanditStats }) {
  const rows = stats.timeline.map((b) => ({ label: shortDate(b.bucket_start), ...b.counts }));
  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
          <CartesianGrid vertical={false} stroke="#d9dfe6" />
          <XAxis dataKey="label" tick={AXIS} tickLine={false} axisLine={{ stroke: "#c6ced8" }} />
          <YAxis allowDecimals={false} tick={AXIS} tickLine={false} axisLine={false} />
          <Tooltip contentStyle={{ borderRadius: 4, borderColor: "#c6ced8", fontSize: 13 }} />
          <Legend iconType="circle" iconSize={9} wrapperStyle={{ fontSize: 13 }} />
          {ACTIONS.map((a) => (
            <Bar
              key={a}
              dataKey={a}
              name={ACTION_LABEL[a]}
              stackId="a"
              fill={DECISION_META[ACTION_DECISION[a]].hex}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function LearningChart({ stats }: { stats: BanditStats }) {
  const rows = stats.reward_trend.map((p, i) => ({ n: i + 1, cumulative: p.cumulative }));
  return (
    <div className="h-56">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={rows} margin={{ top: 8, right: 12, bottom: 0, left: -12 }}>
          <CartesianGrid vertical={false} stroke="#d9dfe6" />
          <XAxis dataKey="n" tick={AXIS} tickLine={false} axisLine={{ stroke: "#c6ced8" }} />
          <YAxis tick={AXIS} tickLine={false} axisLine={false} />
          <ReferenceLine y={0} stroke="#6b7a8d" />
          <Tooltip
            formatter={(v) => [Number(v).toFixed(2), "Total reward"]}
            labelFormatter={(n) => `After verdict ${n}`}
            contentStyle={{ borderRadius: 4, borderColor: "#c6ced8", fontSize: 13 }}
          />
          <Line type="stepAfter" dataKey="cumulative" stroke="#14243a" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

function RiskChart({ trend }: { trend: RiskTrend }) {
  const rows = trend.requests.map((r, i) => ({
    n: i + 1,
    risk: r.attack_probability,
    bias: r.escalation_bias,
  }));
  return (
    <div className="h-56">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={rows} margin={{ top: 8, right: 12, bottom: 0, left: -12 }}>
          <CartesianGrid vertical={false} stroke="#d9dfe6" />
          <XAxis dataKey="n" tick={AXIS} tickLine={false} axisLine={{ stroke: "#c6ced8" }} />
          <YAxis domain={[-0.3, 1]} tick={AXIS} tickLine={false} axisLine={false} />
          <Tooltip
            formatter={(v, name) => [Number(v).toFixed(2), name]}
            labelFormatter={(n) => `Request ${n}`}
            contentStyle={{ borderRadius: 4, borderColor: "#c6ced8", fontSize: 13 }}
          />
          <Legend iconType="plainline" wrapperStyle={{ fontSize: 13 }} />
          <Line dataKey="risk" name="Attack probability" stroke="#a6243a" strokeWidth={2} dot={{ r: 3 }} />
          <Line
            type="stepAfter"
            dataKey="bias"
            name="Session strictness"
            stroke="#5b4bb7"
            strokeWidth={2}
            strokeDasharray="5 4"
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ThreatsView() {
  const [range, setRange] = useState<WindowKey>("7d");
  const teams = useTeams();
  const stats = useGateway(() => {
    const { from, to } = windowRange(range);
    return getBanditStats(from, to, "day");
  }, [range]);
  const sessions = useGateway(getSessions, []);
  const [sessionId, setSessionId] = useState<string>();
  const trend = useGateway(sessionId ? () => getRiskTrend(sessionId) : null, [sessionId]);
  const [unlockMessage, setUnlockMessage] = useState<string>();

  async function unlock(apiKeyId: string) {
    try {
      const result = await unlockApiKey(apiKeyId);
      setUnlockMessage(result.was_locked ? "Unlocked. The key can send requests again." : "That key wasn't locked.");
      trend.reload();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return goToLogin();
      setUnlockMessage(err instanceof Error ? err.message : "Couldn't unlock.");
    }
  }

  const s = stats.data;
  const totalDecisions = s ? Object.values(s.action_counts).reduce((a, b) => a + (b ?? 0), 0) : 0;
  const verdicts = s ? s.reward_trend.length : 0;

  return (
    <>
      <PageHeader
        title="Threats"
        lead="Two layers decide what happens to a suspicious request: a fast per-request defense that learns from reviewers' verdicts, and a session watcher that tightens or locks a key whose recent requests look like an attack in progress."
        actions={
          <Segmented
            label="Time window"
            value={range}
            options={[
              { value: "7d", label: "7 days" },
              { value: "30d", label: "30 days" },
            ]}
            onChange={setRange}
          />
        }
      />

      <Status loading={stats.loading && !s} error={stats.error} onRetry={stats.reload}>
        {s ? (
          <div className="grid gap-10 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
            <section>
              <SectionTitle aside={`${count(totalDecisions)} decisions`}>What the defense chose</SectionTitle>
              {totalDecisions === 0 ? (
                <p className="text-ink-2">No screened requests in this window.</p>
              ) : (
                <ActionChart stats={s} />
              )}
              <ul className="mt-4 flex flex-wrap gap-x-6 gap-y-2 text-sm">
                {ACTIONS.map((a) => (
                  <li key={a}>
                    <DecisionChip decision={ACTION_DECISION[a]}>
                      {ACTION_LABEL[a]}: {count(s.action_counts[a] ?? 0)}
                    </DecisionChip>
                  </li>
                ))}
              </ul>
            </section>

            <section>
              <SectionTitle aside={`${count(verdicts)} verdicts in window`}>Is it learning?</SectionTitle>
              <p className="mb-3 text-sm text-ink-2">
                Every reviewer verdict scores the choice the defense made: positive when it chose well. A rising
                total means it is making better choices.
              </p>
              {verdicts === 0 ? (
                <p className="rounded border border-dashed border-rule px-4 py-6 text-ink-2">
                  No verdicts yet. Decide items in the review queue and the line appears here.
                </p>
              ) : (
                <LearningChart stats={s} />
              )}
              <dl className="mt-4 grid grid-cols-3 gap-4 border-t border-rule pt-3">
                <div>
                  <dt className="text-sm text-ink-2">Updates since last reset</dt>
                  <dd className="figures font-display text-2xl font-semibold">{count(s.model_version)}</dd>
                </div>
                <div>
                  <dt className="text-sm text-ink-2">Average reward</dt>
                  <dd className="figures font-display text-2xl font-semibold">
                    {s.mean_reward === null ? "none yet" : s.mean_reward.toFixed(2)}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm text-ink-2">Waiting for review</dt>
                  <dd className="figures font-display text-2xl font-semibold text-held-ink">
                    {count(s.pending_reviews)}
                  </dd>
                </div>
              </dl>
            </section>
          </div>
        ) : null}
      </Status>

      <section className="mt-12">
        <SectionTitle aside="one session is one API key's requests until it goes quiet for 30 minutes">
          Sessions
        </SectionTitle>
        <Status
          loading={sessions.loading && !sessions.data}
          error={sessions.error}
          onRetry={sessions.reload}
          empty={sessions.data && sessions.data.length === 0 ? "No sessions recorded yet." : undefined}
        >
          <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-ink-2">
                  <tr className="border-b border-rule">
                    <th className="py-2 pr-4 font-semibold">Last seen</th>
                    <th className="py-2 pr-4 font-semibold">Team</th>
                    <th className="py-2 pr-4 font-semibold">Last action</th>
                    <th className="py-2 text-right font-semibold">Strictness</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-rule-soft">
                  {(sessions.data ?? []).map((row) => {
                    const active = row.session_id === sessionId;
                    return (
                      <tr key={row.session_id} className={active ? "bg-sheet" : "hover:bg-surface"}>
                        <td className="py-2 pr-4">
                          <button
                            type="button"
                            onClick={() => {
                              setSessionId(row.session_id);
                              setUnlockMessage(undefined);
                            }}
                            aria-pressed={active}
                            className="whitespace-nowrap font-semibold underline decoration-rule underline-offset-4"
                          >
                            {dateTime(row.last_at)}
                          </button>
                        </td>
                        <td className="py-2 pr-4">{teams.get(row.team_id) ?? "team"}</td>
                        <td className="py-2 pr-4">{SESSION_ACTION_LABEL[row.last_action]}</td>
                        <td className="figures py-2 text-right">{row.last_bias.toFixed(2)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="rounded border border-rule bg-sheet px-5 py-4">
              {!sessionId ? (
                <p className="text-ink-2">Pick a session to see how its risk built up, request by request.</p>
              ) : (
                <Status loading={trend.loading && !trend.data} error={trend.error} onRetry={trend.reload}>
                  {trend.data ? (
                    <>
                      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                        <h3 className="text-lg font-semibold">
                          {count(trend.data.requests.length)} requests in this session
                        </h3>
                        {trend.data.live.locked ? (
                          <div className="flex items-center gap-3">
                            <DecisionChip decision="refused">Key locked out</DecisionChip>
                            <Button tone="primary" onClick={() => unlock(trend.data!.api_key_id)}>
                              Unlock key
                            </Button>
                          </div>
                        ) : trend.data.live.active ? (
                          <DecisionChip decision="allowed">Active</DecisionChip>
                        ) : (
                          <span className="text-sm text-ink-3">Ended</span>
                        )}
                      </div>
                      {unlockMessage ? <p className="mb-2 text-sm font-semibold">{unlockMessage}</p> : null}
                      <RiskChart trend={trend.data} />
                      <p className="mt-2 text-sm text-ink-2">
                        Strictness above 0 makes the per-request defense more cautious for this session; the
                        session watcher raises it when requests look like an attack in progress.
                      </p>
                    </>
                  ) : null}
                </Status>
              )}
            </div>
          </div>
        </Status>
      </section>
    </>
  );
}
