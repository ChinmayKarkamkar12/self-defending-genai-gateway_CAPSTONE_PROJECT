"use client";

import { count } from "@/lib/format";
import type { AuditOutcome, Decision, Overview, RouteStageKey } from "@/lib/types";
import { DECISION_META, STAGE_META } from "@/lib/vocabulary";

// Which outcomes leave the route at each stage, and in which colour. The
// server counts the totals per stage; this only splits them for colour.
const STAGE_OUTCOMES: Record<RouteStageKey, AuditOutcome[]> = {
  intake: ["rejected_streaming"],
  session: ["blocked_session_locked"],
  budget: ["blocked_budget", "blocked_rate_limit"],
  screening: ["blocked_threat", "escalated"],
  provider: ["rejected_unknown_model", "upstream_error"],
  output: ["blocked_output_leak"],
};

const OUTCOME_COLOUR: Partial<Record<AuditOutcome, Decision>> = {
  escalated: "held",
  upstream_error: "failed",
};

const TEXT_HEX: Record<Decision, string> = {
  allowed: "#22604f",
  cleaned: "#7a5714",
  held: "#47399a",
  refused: "#8a1c2f",
  failed: "#505b6b",
};

const W = 1000;
const TOP = 46; // top edge of the band
const MAX_BAND = 64; // band thickness for all of the window's traffic
const MIN_VISIBLE = 2.5; // so a single request still shows
const DROP_TO = 168; // where peeled-off traffic ends
const R0 = 10; // inner radius of the turn
const X0 = 0;
const BAND_START = 118;
const X_END = 836;
const TRAFFIC = "#c4d0dd";

// True proportion, only raised to MIN_VISIBLE for display. The band's own
// width is computed from what's left (not by subtraction), so rounding small
// strands up can never eat the traffic that carries on.
function thickness(value: number, total: number): number {
  if (total === 0 || value === 0) return 0;
  return Math.max((value / total) * MAX_BAND, MIN_VISIBLE);
}

/** One coloured strand turning from the band down and out of the route. */
function strand(cx: number, innerY: number, inner: number, width: number): string {
  const outer = inner + width;
  const cy = innerY + inner;
  return [
    `M ${cx} ${cy - outer}`,
    `A ${outer} ${outer} 0 0 1 ${cx + outer} ${cy}`,
    `L ${cx + outer} ${DROP_TO}`,
    `L ${cx + inner} ${DROP_TO}`,
    `L ${cx + inner} ${cy}`,
    `A ${inner} ${inner} 0 0 0 ${cx} ${cy - inner}`,
    "Z",
  ].join(" ");
}

export function RouteMap({ overview }: { overview: Overview }) {
  const total = overview.total_requests - overview.errors;
  const stages = overview.route;
  const step = (X_END - BAND_START - 30) / stages.length;
  const stationX = stages.map((_, i) => BAND_START + step * (i + 0.6));

  const bands: { x1: number; x2: number; t: number }[] = [];
  const strands: { d: string; colour: string }[] = [];
  let cursor = BAND_START;
  let reaching = total;
  let band = thickness(total, total);
  const stopColour: Decision[] = [];

  stages.forEach((stage, i) => {
    const tIn = band;
    const parts = STAGE_OUTCOMES[stage.key]
      .map((o) => ({ outcome: o, value: overview.outcomes[o] ?? 0 }))
      .filter((p) => p.value > 0);
    const stopWidth = parts.reduce((sum, p) => sum + thickness(p.value, total), 0);
    const turnX = stationX[i] - stopWidth - R0;
    bands.push({ x1: cursor, x2: Math.max(turnX, cursor), t: tIn });

    // Strands from the inside of the turn (bottom of the band) outwards.
    let inner = R0;
    stopColour.push(dominantDecision(overview, stage.key));
    for (const part of parts) {
      const width = thickness(part.value, total);
      const decision = OUTCOME_COLOUR[part.outcome] ?? "refused";
      strands.push({
        d: strand(turnX, TOP + tIn - (inner - R0), inner, width),
        colour: DECISION_META[decision].hex,
      });
      inner += width;
    }
    cursor = Math.max(turnX, cursor);
    reaching -= stage.stopped;
    band = thickness(reaching, total);
  });
  bands.push({ x1: cursor, x2: X_END, t: band });

  const answered = overview.answered;
  const cleaned = overview.decisions.cleaned;

  return (
    <figure className="m-0">
      <RouteList overview={overview} total={total} />
      <div className="hidden overflow-x-auto md:block">
        <svg
          viewBox={`0 0 ${W} 250`}
          className="block h-auto w-full min-w-[760px]"
          role="img"
          aria-labelledby="route-title"
          aria-describedby="route-desc"
        >
          <title id="route-title">Route through the checkpoint</title>
          <desc id="route-desc">
            {`${count(total)} requests entered. ` +
              stages
                .map((s) => `${STAGE_META[s.key].label}: ${count(s.stopped)} stopped`)
                .join(". ") +
              `. ${count(answered)} answered.` +
              (overview.errors > 0 ? ` ${count(overview.errors)} internal errors are not on the route.` : "")}
          </desc>

          {/* Station labels and rules */}
          {stages.map((stage, i) => (
            <g key={stage.key}>
              <line
                x1={stationX[i]}
                x2={stationX[i]}
                y1={TOP - 14}
                y2={DROP_TO + 8}
                stroke="#14243a"
                strokeOpacity={0.18}
                strokeDasharray="2 4"
              />
              <text
                x={stationX[i]}
                y={TOP - 22}
                textAnchor="middle"
                className="fill-ink font-display"
                fontSize={17}
                fontWeight={600}
              >
                {STAGE_META[stage.key].label}
              </text>
              <text
                x={stationX[i]}
                y={DROP_TO + 30}
                textAnchor="middle"
                className="font-display"
                fontSize={24}
                fontWeight={700}
                fill={stage.stopped > 0 ? TEXT_HEX[stopColour[i]] : "#5a697c"}
              >
                {count(stage.stopped)}
              </text>
              <text x={stationX[i]} y={DROP_TO + 50} textAnchor="middle" fontSize={13} className="fill-ink-2">
                {stage.key === "screening" && stage.cleaned > 0
                  ? `stopped, ${count(stage.cleaned)} cleaned`
                  : "stopped"}
              </text>
            </g>
          ))}

          {/* Traffic */}
          {bands.map((b, i) =>
            b.t > 0 && b.x2 > b.x1 ? (
              <rect key={i} x={b.x1} y={TOP} width={b.x2 - b.x1 + 0.5} height={b.t} fill={TRAFFIC} />
            ) : null,
          )}
          {total === 0 ? (
            <line x1={BAND_START} x2={X_END} y1={TOP + 1} y2={TOP + 1} stroke={TRAFFIC} strokeWidth={2} strokeDasharray="6 6" />
          ) : null}
          {strands.map((s, i) => (
            <path key={i} d={s.d} fill={s.colour} />
          ))}

          {/* Entry and exit */}
          <text x={X0} y={TOP + 26} className="font-display fill-ink" fontSize={34} fontWeight={700}>
            {count(total)}
          </text>
          <text x={X0} y={TOP + 46} fontSize={13} className="fill-ink-2">
            requests in
          </text>

          <polygon
            points={`${X_END},${TOP - 6} ${X_END + 18},${TOP + Math.max(band, 2) / 2} ${X_END},${TOP + Math.max(band, 2) + 6}`}
            fill={DECISION_META.allowed.hex}
          />
          <text x={X_END + 32} y={TOP - 22} fontSize={17} fontWeight={600} className="font-display fill-ink">
            Answered
          </text>
          <text x={X_END + 32} y={TOP + 26} className="font-display" fontSize={34} fontWeight={700} fill="#22604f">
            {count(answered)}
          </text>
          {cleaned > 0 ? (
            <text x={X_END + 32} y={TOP + 46} fontSize={13} fill="#7a5714">
              {count(cleaned)} after cleaning
            </text>
          ) : null}
        </svg>
      </div>
      <figcaption className="mt-3 hidden flex-wrap gap-x-6 gap-y-1 text-sm text-ink-2 md:flex">
        <span>Band width is traffic. Where it narrows, a check stopped requests:</span>
        {(["refused", "held", "failed"] as Decision[]).map((d) => (
          <span key={d} className="inline-flex items-center gap-1.5">
            <span aria-hidden className={`h-2.5 w-2.5 rounded-full ${DECISION_META[d].fill}`} />
            {DECISION_META[d].label.toLowerCase()}
          </span>
        ))}
        {overview.errors > 0 ? <span>{count(overview.errors)} internal errors not shown on the route.</span> : null}
      </figcaption>
    </figure>
  );
}

/** The same route as a list, for narrow screens where the drawing won't fit. */
function RouteList({ overview, total }: { overview: Overview; total: number }) {
  return (
    <ol className="space-y-3 md:hidden">
      <li className="flex items-baseline justify-between border-b border-rule-soft pb-2">
        <span className="font-display text-lg font-semibold">In</span>
        <span className="figures font-display text-2xl font-bold">{count(total)}</span>
      </li>
      {overview.route.map((stage) => (
        <li key={stage.key} className="grid grid-cols-[1fr_auto] gap-x-3 border-b border-rule-soft pb-2">
          <span className="font-display text-lg font-semibold">{STAGE_META[stage.key].label}</span>
          <span
            className="figures text-right font-display text-xl font-bold"
            style={{ color: stage.stopped > 0 ? TEXT_HEX[dominantDecision(overview, stage.key)] : "#5a697c" }}
          >
            {count(stage.stopped)}
          </span>
          <span className="text-sm text-ink-2">stops {STAGE_META[stage.key].stops}</span>
          <span className="text-right text-sm text-ink-3">of {count(stage.reached)}</span>
        </li>
      ))}
      <li className="flex items-baseline justify-between">
        <span className="font-display text-lg font-semibold">Answered</span>
        <span className="figures font-display text-2xl font-bold text-allowed-ink">{count(overview.answered)}</span>
      </li>
    </ol>
  );
}

/** The decision that most of a stage's stopped requests got (for colour). */
function dominantDecision(overview: Overview, key: RouteStageKey): Decision {
  const parts = STAGE_OUTCOMES[key].map((o) => ({ o, n: overview.outcomes[o] ?? 0 }));
  const top = parts.reduce((a, b) => (b.n > a.n ? b : a), parts[0]);
  return OUTCOME_COLOUR[top.o] ?? "refused";
}
