"use client";

import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { shortDate } from "@/lib/format";
import type { Timeline } from "@/lib/types";
import { DECISION_META, DECISIONS } from "@/lib/vocabulary";

export function DecisionTimeline({ timeline }: { timeline: Timeline }) {
  const rows = timeline.buckets.map((b) => ({
    label: shortDate(b.bucket_start, timeline.bucket),
    ...b.decisions,
  }));
  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -12 }} barCategoryGap="18%">
          <CartesianGrid vertical={false} stroke="#d9dfe6" />
          <XAxis dataKey="label" tick={{ fill: "#45566c", fontSize: 12 }} tickLine={false} axisLine={{ stroke: "#c6ced8" }} />
          <YAxis allowDecimals={false} tick={{ fill: "#45566c", fontSize: 12 }} tickLine={false} axisLine={false} />
          <Tooltip
            cursor={{ fill: "#14243a", fillOpacity: 0.05 }}
            contentStyle={{ borderRadius: 4, borderColor: "#c6ced8", fontSize: 13 }}
          />
          <Legend iconType="circle" iconSize={9} wrapperStyle={{ fontSize: 13, color: "#45566c" }} />
          {DECISIONS.map((d) => (
            <Bar key={d} dataKey={d} name={DECISION_META[d].label} stackId="decisions" fill={DECISION_META[d].hex} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
