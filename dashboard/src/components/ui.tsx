"use client";

import type { ButtonHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";

import { DECISION_META } from "@/lib/vocabulary";
import type { Decision } from "@/lib/types";

export function PageHeader({
  title,
  lead,
  actions,
}: {
  title: string;
  lead?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="mb-8 flex flex-wrap items-end justify-between gap-x-8 gap-y-4">
      <div className="max-w-2xl">
        <h1 className="text-3xl font-semibold">{title}</h1>
        {lead ? <p className="mt-2 text-ink-2">{lead}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-3">{actions}</div> : null}
    </header>
  );
}

export function SectionTitle({ children, aside }: { children: ReactNode; aside?: ReactNode }) {
  return (
    <div className="mb-3 flex items-baseline justify-between gap-4 border-b border-rule pb-2">
      <h2 className="text-xl font-semibold">{children}</h2>
      {aside ? <div className="text-sm text-ink-3">{aside}</div> : null}
    </div>
  );
}

type Tone = "primary" | "plain" | "danger" | "safe";

const TONES: Record<Tone, string> = {
  primary: "bg-ink text-white hover:bg-[#21385a] disabled:bg-ink-3",
  plain: "bg-sheet text-ink border border-rule hover:border-ink-3 disabled:text-ink-3",
  danger: "bg-refused text-white hover:bg-refused-ink disabled:bg-ink-3",
  safe: "bg-allowed text-white hover:bg-allowed-ink disabled:bg-ink-3",
};

export function Button({
  tone = "plain",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { tone?: Tone }) {
  return (
    <button
      type="button"
      className={`inline-flex min-h-10 items-center justify-center gap-2 rounded px-4 text-sm font-semibold transition-colors disabled:cursor-not-allowed ${TONES[tone]} ${className}`}
      {...props}
    />
  );
}

export function Select({
  label,
  children,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement> & { label: string }) {
  return (
    <label className="flex flex-col gap-1 text-sm text-ink-2">
      {label}
      <select
        className="min-h-10 rounded border border-rule bg-sheet px-3 text-base text-ink"
        {...props}
      >
        {children}
      </select>
    </label>
  );
}

export function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded border border-rule bg-sheet p-0.5">
      {options.map((option) => {
        const selected = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            role="radio"
            aria-checked={selected}
            onClick={() => onChange(option.value)}
            className={`min-h-9 rounded-sm px-3 text-sm font-semibold transition-colors ${
              selected ? "bg-ink text-white" : "text-ink-2 hover:text-ink"
            }`}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}

export function DecisionChip({ decision, children }: { decision: Decision; children?: ReactNode }) {
  const meta = DECISION_META[decision];
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-sm px-1.5 py-0.5 text-sm font-semibold ${meta.wash} ${meta.text}`}
    >
      <span aria-hidden className={`h-2 w-2 rounded-full ${meta.fill}`} />
      {children ?? meta.label}
    </span>
  );
}

/** Loading, error and empty states, said plainly. */
export function Status({
  loading,
  error,
  empty,
  onRetry,
  children,
}: {
  loading?: boolean;
  error?: Error;
  empty?: ReactNode;
  onRetry?: () => void;
  children?: ReactNode;
}) {
  if (error) {
    return (
      <div role="alert" className="rounded border-l-4 border-refused bg-refused-wash px-4 py-3 text-refused-ink">
        <p className="font-semibold">Couldn&apos;t load this: {error.message}</p>
        {onRetry ? (
          <button type="button" onClick={onRetry} className="mt-1 underline underline-offset-2">
            Try again
          </button>
        ) : null}
      </div>
    );
  }
  if (loading) {
    return (
      <p className="py-6 text-ink-3" aria-live="polite">
        Loading…
      </p>
    );
  }
  if (empty) {
    return <div className="rounded border border-dashed border-rule px-4 py-6 text-ink-2">{empty}</div>;
  }
  return <>{children}</>;
}
