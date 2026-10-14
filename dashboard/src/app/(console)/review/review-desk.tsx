"use client";

import { useEffect, useState } from "react";

import { useTeams } from "@/components/team-picker";
import { Button, DecisionChip, PageHeader, SectionTitle, Status } from "@/components/ui";
import {
  amendReviewDecision,
  ApiError,
  getReviewQueue,
  submitReviewDecision,
} from "@/lib/api-client";
import { count, dateTime, probability } from "@/lib/format";
import type { ReviewItem, ThreatLabel } from "@/lib/types";
import { goToLogin, useGateway } from "@/lib/use-gateway";
import { ACTION_DECISION, ACTION_LABEL } from "@/lib/vocabulary";

const REASON: Record<ReviewItem["reason"], string> = {
  escalation: "The defense wasn't sure and asked for a person",
  spot_check: "Random check of a decision the defense made on its own",
  output_scan: "The model's reply leaked its instructions",
};

const REASON_SHORT: Record<ReviewItem["reason"], string> = {
  escalation: "Held for a person",
  spot_check: "Spot check",
  output_scan: "Leaked reply",
};

const SCORE_LABEL: Record<string, string> = {
  benign: "Harmless",
  prompt_injection: "Prompt injection",
  jailbreak: "Jailbreak",
};

function Scores({ scores }: { scores: Record<string, number> }) {
  return (
    <ul className="space-y-2">
      {Object.entries(scores).map(([label, value]) => (
        <li key={label} className="grid grid-cols-[9rem_1fr_3rem] items-center gap-3 text-sm">
          <span className="text-ink-2">{SCORE_LABEL[label] ?? label}</span>
          <span className="h-2 rounded-full bg-rule-soft">
            <span
              className={`block h-full rounded-full ${label === "benign" ? "bg-allowed" : "bg-refused"}`}
              style={{ width: `${Math.max(value * 100, 1)}%` }}
            />
          </span>
          <span className="figures text-right font-semibold">{probability(value)}</span>
        </li>
      ))}
    </ul>
  );
}

interface Result {
  decision: ThreatLabel;
  amended: boolean;
  reward: number | null;
  learned: boolean;
}

export function ReviewDesk() {
  const pending = useGateway(() => getReviewQueue("pending"), []);
  const recent = useGateway(() => getReviewQueue("reviewed", 8), []);
  const teams = useTeams();
  // Decided here since the queue was loaded: hidden without a reload.
  const [decided, setDecided] = useState<Set<string>>(new Set());
  const [selectedId, setSelectedId] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>();
  const [error, setError] = useState<string>();

  const items = (pending.data ?? []).filter((item) => !decided.has(item.id));
  const selected = items.find((item) => item.id === selectedId) ?? items[0];

  async function decide(decision: ThreatLabel) {
    if (!selected || busy) return;
    setBusy(true);
    setError(undefined);
    try {
      const outcome = await submitReviewDecision(selected.id, decision);
      setResult({
        decision,
        amended: false,
        reward: outcome.reward_applied,
        learned: outcome.bandit_updated,
      });
      setDecided((current) => new Set(current).add(selected.id));
      setSelectedId(items.find((item) => item.id !== selected.id)?.id);
      recent.reload();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return goToLogin();
      setError(err instanceof Error ? err.message : "couldn't save the decision");
      if (err instanceof ApiError && err.status === 409) pending.reload();
    } finally {
      setBusy(false);
    }
  }

  async function amend(item: ReviewItem) {
    const decision: ThreatLabel = item.decision === "attack" ? "benign" : "attack";
    setError(undefined);
    try {
      const outcome = await amendReviewDecision(item.id, decision);
      setResult({
        decision,
        amended: true,
        reward: outcome.reward_applied,
        learned: outcome.bandit_updated,
      });
      recent.reload();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return goToLogin();
      setError(err instanceof Error ? err.message : "couldn't change the decision");
    }
  }

  // A and S decide the open item from the keyboard.
  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement;
      if (target.closest("input, textarea, select") || event.metaKey || event.ctrlKey) return;
      if (event.key === "a") void decide("attack");
      if (event.key === "s") void decide("benign");
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  return (
    <>
      <PageHeader
        title="Review queue"
        lead="Requests the defense held back or picked for a spot check. Your verdict doesn't change what already happened to the request; it teaches the defense what to do next time."
      />

      {result ? (
        <div role="status" className="mb-6 rounded border-l-4 border-ink bg-sheet px-4 py-3">
          <p className="font-semibold">
            {result.amended ? "Changed to" : "Marked as"}{" "}
            {result.decision === "attack" ? "an attack" : "safe"}.
            {result.learned ? " The defense learned from it" : " Saved"}
            {result.reward !== null
              ? ` (reward ${result.reward > 0 ? "+" : ""}${result.reward.toFixed(2)}).`
              : "."}
          </p>
        </div>
      ) : null}
      {error ? (
        <p role="alert" className="mb-6 rounded bg-refused-wash px-4 py-3 text-refused-ink">
          {error}
        </p>
      ) : null}

      <Status
        loading={pending.loading && !pending.data}
        error={pending.error}
        onRetry={pending.reload}
        empty={
          pending.data && items.length === 0
            ? "Nothing is waiting for review. Held requests appear here as they happen."
            : undefined
        }
      >
        <div className="grid gap-8 lg:grid-cols-[18rem_minmax(0,1fr)]">
          <nav aria-label="Waiting for review">
            <p className="mb-2 text-sm text-ink-2">{count(items.length)} waiting</p>
            <ul className="divide-y divide-rule border-y border-rule">
              {items.map((item) => {
                const active = item.id === selected?.id;
                return (
                  <li key={item.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedId(item.id)}
                      aria-current={active ? "true" : undefined}
                      className={`block w-full border-l-4 px-3 py-3 text-left ${
                        active ? "border-held bg-sheet" : "border-transparent hover:bg-surface"
                      }`}
                    >
                      <span className="block text-sm font-semibold">{REASON_SHORT[item.reason]}</span>
                      <span className="block text-sm text-ink-2">
                        {dateTime(item.created_at)}, {teams.get(item.team_id) ?? "team"}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </nav>

          {selected ? (
            <article aria-labelledby="case-title" className="rounded border border-rule bg-sheet">
              <header className="border-b border-rule px-6 py-4">
                <h2 id="case-title" className="text-2xl font-semibold">
                  Is this an attack?
                </h2>
                <p className="mt-1 text-ink-2">{REASON[selected.reason]}.</p>
              </header>

              <div className="grid gap-8 px-6 py-5 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
                <section>
                  <h3 className="mb-1 text-lg font-semibold">What the application sent</h3>
                  <p className="mb-2 text-sm text-ink-3">
                    Personal data was removed by the gateway before this was stored.
                  </p>
                  <blockquote className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded border-l-4 border-rule bg-surface px-4 py-3 text-[0.95rem] leading-relaxed">
                    {selected.prompt_excerpt || "(empty)"}
                  </blockquote>
                </section>
                <section className="space-y-5">
                  <div>
                    <h3 className="mb-2 text-lg font-semibold">What the gateway did</h3>
                    <DecisionChip decision={ACTION_DECISION[selected.outcome]}>
                      {ACTION_LABEL[selected.outcome]}
                    </DecisionChip>
                    {selected.action_taken !== selected.outcome ? (
                      <p className="mt-1 text-sm text-ink-2">
                        The defense chose &ldquo;{ACTION_LABEL[selected.action_taken]}&rdquo;; it was
                        carried out as &ldquo;{ACTION_LABEL[selected.outcome]}&rdquo;.
                      </p>
                    ) : null}
                  </div>
                  <div>
                    <h3 className="mb-2 text-lg font-semibold">Classifier scores</h3>
                    <Scores scores={selected.threat_score} />
                    <p className="mt-2 text-sm text-ink-2">
                      Defense confidence {probability(selected.bandit_confidence)} (0 means no feedback
                      yet).
                    </p>
                  </div>
                </section>
              </div>

              <footer className="flex flex-wrap items-center gap-3 border-t border-rule bg-surface px-6 py-4">
                <Button tone="danger" onClick={() => decide("attack")} disabled={busy}>
                  It&apos;s an attack
                </Button>
                <Button tone="safe" onClick={() => decide("benign")} disabled={busy}>
                  It&apos;s safe
                </Button>
                <span className="text-sm text-ink-3">
                  Keys: <kbd className="rounded border border-rule bg-sheet px-1">A</kbd> attack,{" "}
                  <kbd className="rounded border border-rule bg-sheet px-1">S</kbd> safe
                </span>
              </footer>
            </article>
          ) : null}
        </div>
      </Status>

      <section className="mt-12">
        <SectionTitle aside="a wrong verdict can be changed; the old one is kept">
          Recently decided
        </SectionTitle>
        <Status
          loading={recent.loading && !recent.data}
          error={recent.error}
          empty={recent.data && recent.data.length === 0 ? "No verdicts yet." : undefined}
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-ink-2">
                <tr className="border-b border-rule">
                  <th className="py-2 pr-4 font-semibold">Decided</th>
                  <th className="py-2 pr-4 font-semibold">By</th>
                  <th className="py-2 pr-4 font-semibold">Verdict</th>
                  <th className="py-2 pr-4 font-semibold">Excerpt</th>
                  <th className="py-2">
                    <span className="sr-only">Change</span>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-rule-soft">
                {(recent.data ?? []).map((item) => (
                  <tr key={item.id}>
                    <td className="whitespace-nowrap py-2 pr-4">
                      {item.reviewed_at ? dateTime(item.reviewed_at) : ""}
                    </td>
                    <td className="py-2 pr-4">{item.reviewer}</td>
                    <td className="py-2 pr-4">
                      <DecisionChip decision={item.decision === "attack" ? "refused" : "allowed"}>
                        {item.decision === "attack" ? "Attack" : "Safe"}
                      </DecisionChip>
                    </td>
                    <td className="max-w-md truncate py-2 pr-4 text-ink-2">{item.prompt_excerpt}</td>
                    <td className="whitespace-nowrap py-2 text-right">
                      <button
                        type="button"
                        onClick={() => amend(item)}
                        className="font-semibold underline underline-offset-2"
                      >
                        Change to {item.decision === "attack" ? "safe" : "attack"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Status>
      </section>
    </>
  );
}
