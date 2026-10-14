"use client";

import Link from "next/link";
import { useState } from "react";

import { ChainCheck } from "@/components/chain-check";
import { DecisionTimeline } from "@/components/decision-timeline";
import { RouteMap } from "@/components/route-map";
import { PageHeader, Segmented, SectionTitle, Status } from "@/components/ui";
import { getOverview, getTimeline } from "@/lib/api-client";
import { count, money, percent, windowRange, type WindowKey } from "@/lib/format";
import { useGateway } from "@/lib/use-gateway";
import { entityLabel } from "@/lib/vocabulary";

const WINDOWS: { value: WindowKey; label: string }[] = [
  { value: "today", label: "Today" },
  { value: "7d", label: "7 days" },
  { value: "30d", label: "30 days" },
];

const TITLES: Record<WindowKey, string> = {
  today: "Today at the checkpoint",
  "7d": "The last 7 days",
  "30d": "The last 30 days",
};

export function OverviewView() {
  const [range, setRange] = useState<WindowKey>("today");
  const overview = useGateway(() => {
    const { from, to } = windowRange(range);
    return getOverview(from, to);
  }, [range]);
  const timeline = useGateway(() => {
    const { from, to } = windowRange(range === "today" ? "7d" : range);
    return getTimeline(from, to, "day");
  }, [range]);

  const o = overview.data;
  const stopped = o ? o.decisions.refused + o.decisions.held : 0;
  const piiTotal = o ? Object.values(o.pii_entities).reduce((a, b) => a + b, 0) : 0;
  const piiMax = o ? Math.max(1, ...Object.values(o.pii_entities)) : 1;

  return (
    <>
      <PageHeader
        title={TITLES[range]}
        lead="Every request an application sends passes these checks before it reaches a model. The band is the traffic; each check takes out what it stops."
        actions={<Segmented label="Time window" value={range} options={WINDOWS} onChange={setRange} />}
      />

      <section aria-label="Route through the checkpoint" className="rounded border border-rule bg-sheet px-6 pb-5 pt-6">
        <Status loading={overview.loading && !o} error={overview.error} onRetry={overview.reload}>
          {o ? <RouteMap overview={o} /> : null}
        </Status>
      </section>

      {o ? (
        <dl className="mt-8 grid grid-cols-2 gap-y-6 border-y border-rule py-5 sm:grid-cols-3 lg:grid-cols-6 lg:divide-x lg:divide-rule">
          <Figure term="Requests" value={count(o.total_requests)} />
          <Figure term="Answered" value={count(o.answered)} note={percent(o.answered, o.total_requests)} />
          <Figure term="Stopped" value={count(stopped)} note={`${count(o.decisions.failed)} failed`} tone="refused" />
          <Figure
            term="Waiting for review"
            value={count(o.pending_reviews)}
            tone={o.pending_reviews > 0 ? "held" : undefined}
            link={o.pending_reviews > 0 ? { href: "/review", label: "Review now" } : undefined}
          />
          <Figure term="Spend" value={money(o.spend_usd)} note={`${count(o.tokens_in + o.tokens_out)} tokens`} />
          <Figure term="Personal data removed" value={count(piiTotal)} note="items" tone="cleaned" />
        </dl>
      ) : null}

      <div className="mt-10 grid gap-10 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <section>
          <SectionTitle aside={range === "today" ? "last 7 days, per day" : "per day"}>
            Decisions over time
          </SectionTitle>
          <Status
            loading={timeline.loading && !timeline.data}
            error={timeline.error}
            onRetry={timeline.reload}
            empty={timeline.data && timeline.data.buckets.length === 0 ? "No requests in this window yet." : undefined}
          >
            {timeline.data ? <DecisionTimeline timeline={timeline.data} /> : null}
          </Status>
        </section>

        <div className="space-y-10">
          <section>
            <SectionTitle>Audit log integrity</SectionTitle>
            <ChainCheck compact />
          </section>

          <section>
            <SectionTitle aside="found in prompts, then removed">Personal data</SectionTitle>
            {o && piiTotal === 0 ? <p className="text-ink-2">None found in this window.</p> : null}
            <ul className="space-y-2">
              {o
                ? Object.entries(o.pii_entities).map(([entity, n]) => (
                    <li key={entity} className="grid grid-cols-[1fr_auto] items-center gap-x-3 text-sm">
                      <span>{entityLabel(entity)}</span>
                      <span className="figures font-semibold">{count(n)}</span>
                      <span className="col-span-2 h-1.5 rounded-full bg-rule-soft">
                        <span
                          className="block h-full rounded-full bg-cleaned"
                          style={{ width: `${(n / piiMax) * 100}%` }}
                        />
                      </span>
                    </li>
                  ))
                : null}
            </ul>
          </section>
        </div>
      </div>
    </>
  );
}

const FIGURE_TONE = {
  refused: "text-refused-ink",
  held: "text-held-ink",
  cleaned: "text-cleaned-ink",
} as const;

function Figure({
  term,
  value,
  note,
  tone,
  link,
}: {
  term: string;
  value: string;
  note?: string;
  tone?: keyof typeof FIGURE_TONE;
  link?: { href: string; label: string };
}) {
  return (
    <div className="lg:px-5 lg:first:pl-0">
      <dt className="text-sm text-ink-2">{term}</dt>
      <dd className={`figures mt-1 font-display text-3xl font-semibold ${tone ? FIGURE_TONE[tone] : "text-ink"}`}>
        {value}
      </dd>
      {note ? <dd className="text-sm text-ink-3">{note}</dd> : null}
      {link ? (
        <dd>
          <Link href={link.href} className="text-sm font-semibold text-held-ink underline underline-offset-2">
            {link.label}
          </Link>
        </dd>
      ) : null}
    </div>
  );
}
