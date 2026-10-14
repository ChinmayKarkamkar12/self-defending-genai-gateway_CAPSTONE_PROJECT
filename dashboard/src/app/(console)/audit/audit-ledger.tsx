"use client";

import { Fragment, useEffect, useState, type FormEvent } from "react";

import { ChainCheck } from "@/components/chain-check";
import { TeamPicker, useTeams } from "@/components/team-picker";
import { Button, DecisionChip, PageHeader, SectionTitle, Select, Status } from "@/components/ui";
import { ApiError, auditExportUrl, getAuditLogs } from "@/lib/api-client";
import { count, dateTime, money, probability, shortHash } from "@/lib/format";
import type { AuditLogEntry, AuditLogFilters, AuditOutcome } from "@/lib/types";
import { goToLogin } from "@/lib/use-gateway";
import { entityLabel, OUTCOME_DECISION, OUTCOME_LABEL } from "@/lib/vocabulary";

const PAGE = 50;

function topThreat(score: Record<string, number> | null): string {
  if (!score) return "not scored";
  const attack = Math.max(score.prompt_injection ?? 0, score.jailbreak ?? 0);
  return probability(attack);
}

function piiSummary(summary: Record<string, number>): string {
  const entries = Object.entries(summary);
  if (entries.length === 0) return "none";
  return entries.map(([e, n]) => `${n} ${entityLabel(e).toLowerCase()}`).join(", ");
}

// A date picked in the form covers that whole day (UTC).
function toFilters(form: FormData, teamId: string | undefined): AuditLogFilters {
  const from = String(form.get("from") || "");
  const to = String(form.get("to") || "");
  const outcome = String(form.get("outcome") || "");
  return {
    team_id: teamId,
    from: from ? `${from}T00:00:00Z` : undefined,
    to: to ? `${to}T23:59:59.999Z` : undefined,
    outcome: (outcome || undefined) as AuditOutcome | undefined,
  };
}

export function AuditLedger() {
  const teams = useTeams();
  const [teamId, setTeamId] = useState<string>();
  const [filters, setFilters] = useState<AuditLogFilters>({});
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error>();
  const [open, setOpen] = useState<string>();

  function fetchPage(f: AuditLogFilters, before?: number) {
    return getAuditLogs(f, before, PAGE).then(
      (page) => {
        setEntries((current) => (before ? [...current, ...page.entries] : page.entries));
        setNext(page.next_before_sequence);
        setLoading(false);
      },
      (err: unknown) => {
        if (err instanceof ApiError && err.status === 401) return goToLogin();
        setError(err instanceof Error ? err : new Error(String(err)));
        setLoading(false);
      },
    );
  }

  function load(f: AuditLogFilters, before?: number) {
    setLoading(true);
    setError(undefined);
    void fetchPage(f, before);
  }

  // First page on arrival (state is only set once it answers).
  useEffect(() => {
    void fetchPage({});
     
  }, []);

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const f = toFilters(new FormData(event.currentTarget), teamId);
    setFilters(f);
    void load(f);
  }

  return (
    <>
      <PageHeader
        title="Audit log"
        lead="One entry for every request, whatever happened to it. Each entry carries a hash of its own contents and of the entry before it, so changing any past entry breaks the chain from that point on."
        actions={
          <a
            href={auditExportUrl(filters)}
            className="inline-flex min-h-10 items-center rounded border border-rule bg-sheet px-4 text-sm font-semibold hover:border-ink-3"
          >
            Download CSV
          </a>
        }
      />

      <section className="mb-10 rounded border border-rule bg-sheet px-6 py-5">
        <h2 className="mb-3 text-xl font-semibold">Has anyone changed the log?</h2>
        <ChainCheck />
      </section>

      <form
        onSubmit={applyFilters}
        aria-label="Filter entries"
        className="mb-4 flex flex-wrap items-end gap-4"
      >
        <TeamPicker value={teamId} onChange={setTeamId} allowAll />
        <Select label="What happened" name="outcome" defaultValue="">
          <option value="">Anything</option>
          {(Object.keys(OUTCOME_LABEL) as AuditOutcome[]).map((o) => (
            <option key={o} value={o}>
              {OUTCOME_LABEL[o]}
            </option>
          ))}
        </Select>
        <label className="flex flex-col gap-1 text-sm text-ink-2">
          From
          <input type="date" name="from" className="min-h-10 rounded border border-rule bg-sheet px-3 text-base text-ink" />
        </label>
        <label className="flex flex-col gap-1 text-sm text-ink-2">
          To
          <input type="date" name="to" className="min-h-10 rounded border border-rule bg-sheet px-3 text-base text-ink" />
        </label>
        <Button type="submit" tone="primary">
          Show entries
        </Button>
      </form>

      <SectionTitle aside={entries.length ? `showing ${count(entries.length)}, newest first` : undefined}>
        Entries
      </SectionTitle>
      <Status
        loading={loading && entries.length === 0}
        error={error}
        onRetry={() => load(filters)}
        empty={!loading && entries.length === 0 ? "No entries match these filters." : undefined}
      >
        <div className="overflow-x-auto rounded border border-rule bg-sheet">
          <table className="w-full min-w-[1100px] text-left text-sm">
            <thead className="bg-surface text-ink-2">
              <tr className="border-b border-rule">
                <th className="w-16 py-2 pl-4 pr-3 text-right font-semibold">#</th>
                <th className="py-2 pr-4 font-semibold">Time</th>
                <th className="py-2 pr-4 font-semibold">Team</th>
                <th className="py-2 pr-4 font-semibold">What happened</th>
                <th className="py-2 pr-4 font-semibold">Model</th>
                <th className="whitespace-nowrap py-2 pr-4 text-right font-semibold">Attack score</th>
                <th className="py-2 pr-4 font-semibold">Personal data</th>
                <th className="py-2 pr-4 text-right font-semibold">Cost</th>
                <th className="py-2 pr-4 font-semibold">Hash link</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => {
                const expanded = open === e.id;
                return (
                  <Fragment key={e.id}>
                    <tr
                      className={`border-b border-rule-soft align-top hover:bg-surface ${expanded ? "bg-surface" : ""}`}
                    >
                      <td className="figures py-2 pl-4 pr-3 text-right text-ink-3">{e.sequence_number}</td>
                      <td className="whitespace-nowrap py-2 pr-4">{dateTime(e.timestamp)}</td>
                      <td className="whitespace-nowrap py-2 pr-4">{teams.get(e.team_id) ?? shortHash(e.team_id)}</td>
                      <td className="py-2 pr-4">
                        <DecisionChip decision={OUTCOME_DECISION[e.outcome]}>{OUTCOME_LABEL[e.outcome]}</DecisionChip>
                      </td>
                      <td className="whitespace-nowrap py-2 pr-4 text-ink-2">{e.model}</td>
                      <td className="figures py-2 pr-4 text-right">{topThreat(e.threat_score)}</td>
                      <td className="py-2 pr-4 text-ink-2">{piiSummary(e.redaction_summary)}</td>
                      <td className="figures py-2 pr-4 text-right">{money(e.cost_usd)}</td>
                      <td className="py-2 pr-4">
                        <button
                          type="button"
                          onClick={() => setOpen(expanded ? undefined : e.id)}
                          aria-expanded={expanded}
                          className="figures whitespace-nowrap text-ink-2 underline decoration-rule underline-offset-4 hover:text-ink"
                          title="Show this entry's details"
                        >
                          {shortHash(e.prev_hash)} to {shortHash(e.entry_hash)}
                        </button>
                      </td>
                    </tr>
                    {expanded ? (
                      <tr className="border-b border-rule bg-surface">
                        <td />
                        <td colSpan={8} className="pb-4 pr-4">
                          <dl className="grid gap-x-8 gap-y-2 sm:grid-cols-2 lg:grid-cols-3">
                            <Detail term="Request ID" value={e.request_id} />
                            <Detail term="HTTP status" value={String(e.http_status)} />
                            <Detail term="Stopped at" value={e.pipeline_stage ?? "nowhere"} />
                            <Detail term="Defense action" value={e.action_taken} />
                            <Detail term="Session action" value={e.session_action ?? "none"} />
                            <Detail term="Tokens" value={`${count(e.tokens_in)} in, ${count(e.tokens_out)} out`} />
                            <Detail term="Latency" value={`${count(e.latency_ms)} ms`} />
                            <Detail
                              term="Reply check"
                              value={
                                e.output_flags
                                  ? e.output_flags.system_prompt_leaked
                                    ? "leaked instructions"
                                    : "clean"
                                  : "not run"
                              }
                            />
                            <Detail term="Previous hash" value={e.prev_hash} mono />
                            <Detail term="This entry's hash" value={e.entry_hash} mono />
                          </dl>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
        {next !== null ? (
          <div className="mt-4">
            <Button onClick={() => load(filters, next)} disabled={loading}>
              {loading ? "Loading…" : "Show older entries"}
            </Button>
          </div>
        ) : null}
      </Status>
    </>
  );
}

function Detail({ term, value, mono = false }: { term: string; value: string; mono?: boolean }) {
  return (
    <div className={mono ? "sm:col-span-2 lg:col-span-3" : undefined}>
      <dt className="text-xs text-ink-3">{term}</dt>
      <dd className={`break-all ${mono ? "figures text-xs" : ""}`}>{value}</dd>
    </div>
  );
}
