"use client";

import { useState, type FormEvent } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { TeamPicker } from "@/components/team-picker";
import { Button, PageHeader, Segmented, SectionTitle, Select, Status } from "@/components/ui";
import { ApiError, getBudget, getSpend, putBudget } from "@/lib/api-client";
import { count, money, shortDate, windowRange, type WindowKey } from "@/lib/format";
import type { BudgetPeriod, BudgetPolicy, Spend } from "@/lib/types";
import { goToLogin, useGateway } from "@/lib/use-gateway";

// Model colours: distinct from the decision colours, which mean something else.
const MODEL_COLOURS = ["#14243a", "#4f7cac", "#8fb0d0", "#6d6a8f", "#9aa4ae", "#3d6b6b"];

function Gauge({ budget }: { budget: BudgetPolicy }) {
  const spent = Number(budget.current_spend_usd);
  const limit = Number(budget.limit_usd);
  const share = limit > 0 ? Math.min(spent / limit, 1) : 1;
  const tone = share >= 1 ? "bg-refused" : share >= 0.8 ? "bg-cleaned" : "bg-allowed";
  return (
    <div>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="figures font-display text-3xl font-semibold">
          {money(spent)} <span className="text-lg font-medium text-ink-2">of {money(limit)}</span>
        </p>
        <p className="text-ink-2">
          {money(budget.remaining_usd)} left {budget.period === "daily" ? "today" : "this month"}
        </p>
      </div>
      <div
        className="relative mt-3 h-4 rounded-sm bg-rule-soft"
        role="meter"
        aria-valuemin={0}
        aria-valuemax={limit}
        aria-valuenow={spent}
        aria-label="Spend against budget"
      >
        <div className={`h-full rounded-sm ${tone}`} style={{ width: `${share * 100}%` }} />
        {[0.25, 0.5, 0.75].map((t) => (
          <span key={t} aria-hidden className="absolute top-0 h-full w-px bg-ground" style={{ left: `${t * 100}%` }} />
        ))}
      </div>
      <p className="mt-2 text-sm text-ink-2">
        Requests are refused once the budget is used up, and above {count(budget.rate_limit_rps)} per second.
      </p>
    </div>
  );
}

function BudgetForm({
  teamId,
  budget,
  onSaved,
}: {
  teamId: string;
  budget: BudgetPolicy | undefined;
  onSaved: () => void;
}) {
  const [message, setMessage] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setMessage(undefined);
    try {
      await putBudget(teamId, {
        period: form.get("period") as BudgetPeriod,
        limit_usd: String(form.get("limit")),
        rate_limit_rps: Number(form.get("rps")),
      });
      setMessage("Budget saved.");
      onSaved();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return goToLogin();
      setMessage(err instanceof Error ? err.message : "Couldn't save the budget.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={save} key={teamId + (budget?.limit_usd ?? "")} className="flex flex-wrap items-end gap-4">
      <Select label="Period" name="period" defaultValue={budget?.period ?? "daily"}>
        <option value="daily">Per day</option>
        <option value="monthly">Per month</option>
      </Select>
      <label className="flex flex-col gap-1 text-sm text-ink-2">
        Limit in USD
        <input
          name="limit"
          type="number"
          min="0"
          step="0.01"
          required
          defaultValue={budget ? Number(budget.limit_usd) : 10}
          className="figures min-h-10 w-32 rounded border border-rule bg-sheet px-3 text-base text-ink"
        />
      </label>
      <label className="flex flex-col gap-1 text-sm text-ink-2">
        Requests per second
        <input
          name="rps"
          type="number"
          min="1"
          step="1"
          required
          defaultValue={budget?.rate_limit_rps ?? 10}
          className="figures min-h-10 w-32 rounded border border-rule bg-sheet px-3 text-base text-ink"
        />
      </label>
      <Button type="submit" tone="primary" disabled={busy}>
        {busy ? "Saving…" : budget ? "Save budget" : "Set budget"}
      </Button>
      {message ? (
        <p role="status" className="w-full text-sm font-semibold">
          {message}
        </p>
      ) : null}
    </form>
  );
}

function SpendChart({ spend }: { spend: Spend }) {
  const models = [...new Set(spend.points.map((p) => p.model))];
  const byDay = new Map<string, Record<string, number | string>>();
  for (const p of spend.points) {
    const row = byDay.get(p.bucket_start) ?? { label: shortDate(p.bucket_start) };
    row[p.model] = Number(row[p.model] ?? 0) + Number(p.cost_usd);
    byDay.set(p.bucket_start, row);
  }
  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={[...byDay.values()]} margin={{ top: 8, right: 8, bottom: 0, left: 4 }}>
          <CartesianGrid vertical={false} stroke="#d9dfe6" />
          <XAxis dataKey="label" tick={{ fill: "#45566c", fontSize: 12 }} tickLine={false} axisLine={{ stroke: "#c6ced8" }} />
          <YAxis tickFormatter={(v) => money(v)} tick={{ fill: "#45566c", fontSize: 12 }} tickLine={false} axisLine={false} />
          <Tooltip formatter={(v) => money(Number(v))} contentStyle={{ borderRadius: 4, borderColor: "#c6ced8", fontSize: 13 }} />
          <Legend iconType="square" iconSize={9} wrapperStyle={{ fontSize: 13 }} />
          {models.map((m, i) => (
            <Bar key={m} dataKey={m} stackId="m" fill={MODEL_COLOURS[i % MODEL_COLOURS.length]} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function CostView() {
  const [teamId, setTeamId] = useState<string>();
  const [range, setRange] = useState<WindowKey>("7d");
  const budget = useGateway(teamId ? () => getBudget(teamId) : null, [teamId]);
  const spend = useGateway(
    teamId
      ? () => {
          const { from, to } = windowRange(range);
          return getSpend(from, to, teamId);
        }
      : null,
    [teamId, range],
  );

  const noBudget = budget.error instanceof ApiError && budget.error.status === 404;
  const models = new Map<string, { requests: number; tokens: number; cost: number }>();
  for (const p of spend.data?.points ?? []) {
    const m = models.get(p.model) ?? { requests: 0, tokens: 0, cost: 0 };
    m.requests += p.requests;
    m.tokens += p.tokens_in + p.tokens_out;
    m.cost += Number(p.cost_usd);
    models.set(p.model, m);
  }

  return (
    <>
      <PageHeader
        title="Cost & usage"
        lead="What each team spends on model calls, and the limits that stop a runaway application from spending more."
        actions={<TeamPicker value={teamId} onChange={setTeamId} />}
      />

      <section className="rounded border border-rule bg-sheet px-6 py-5">
        <h2 className="mb-4 text-xl font-semibold">Budget</h2>
        {teamId ? (
          <>
            {noBudget ? (
              <p className="mb-4 rounded border-l-4 border-cleaned bg-cleaned-wash px-4 py-3 text-cleaned-ink">
                No budget set for this team, so its spending is unlimited. Set one below.
              </p>
            ) : (
              <Status loading={budget.loading && !budget.data} error={budget.error} onRetry={budget.reload}>
                {budget.data ? <Gauge budget={budget.data} /> : null}
              </Status>
            )}
            <div className="mt-6 border-t border-rule-soft pt-5">
              <BudgetForm teamId={teamId} budget={budget.data} onSaved={budget.reload} />
            </div>
          </>
        ) : (
          <p className="text-ink-2">Loading teams…</p>
        )}
      </section>

      <section className="mt-10">
        <SectionTitle
          aside={
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
        >
          Spend by model
        </SectionTitle>
        <Status
          loading={spend.loading && !spend.data}
          error={spend.error}
          onRetry={spend.reload}
          empty={spend.data && spend.data.points.length === 0 ? "No answered requests in this window." : undefined}
        >
          {spend.data ? (
            <div className="grid gap-8 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
              <SpendChart spend={spend.data} />
              <table className="w-full self-start text-left text-sm">
                <thead className="text-ink-2">
                  <tr className="border-b border-rule">
                    <th className="py-2 pr-4 font-semibold">Model</th>
                    <th className="py-2 pr-4 text-right font-semibold">Requests</th>
                    <th className="py-2 pr-4 text-right font-semibold">Tokens</th>
                    <th className="py-2 text-right font-semibold">Cost</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-rule-soft">
                  {[...models.entries()].map(([model, m]) => (
                    <tr key={model}>
                      <td className="py-2 pr-4">{model}</td>
                      <td className="figures py-2 pr-4 text-right">{count(m.requests)}</td>
                      <td className="figures py-2 pr-4 text-right">{count(m.tokens)}</td>
                      <td className="figures py-2 text-right">{money(m.cost)}</td>
                    </tr>
                  ))}
                  <tr className="border-t border-rule font-semibold">
                    <td className="py-2 pr-4">Total</td>
                    <td />
                    <td />
                    <td className="figures py-2 text-right">{money(spend.data.total_usd)}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          ) : null}
        </Status>
      </section>
    </>
  );
}
