"use client";

import Link from "next/link";
import { useState } from "react";

import { ApiError, verifyAuditLog } from "@/lib/api-client";
import { count, shortHash } from "@/lib/format";
import type { VerifyResult } from "@/lib/types";
import { goToLogin } from "@/lib/use-gateway";
import { Button } from "./ui";

/** Links of a chain: drawn intact, or broken at the entry that fails. */
function ChainLinks({ result }: { result: VerifyResult }) {
  const links = 9;
  const brokenAt = result.valid ? -1 : Math.min(links - 3, 4);
  return (
    <svg viewBox="0 0 270 30" className="h-7 w-auto" aria-hidden>
      {Array.from({ length: links }, (_, i) => {
        const broken = i === brokenAt;
        const after = brokenAt >= 0 && i > brokenAt;
        const colour = broken ? "#a6243a" : after ? "#c6ced8" : "#2f7d6b";
        return (
          <g key={i} transform={`translate(${i * 29 + 4} ${broken ? 4 : 0})`}>
            <rect
              x="0"
              y="8"
              width="34"
              height="14"
              rx="7"
              fill="none"
              stroke={colour}
              strokeWidth="3.5"
              strokeDasharray={broken ? "10 6" : undefined}
            />
          </g>
        );
      })}
    </svg>
  );
}

export function ChainCheck({ compact = false }: { compact?: boolean }) {
  const [result, setResult] = useState<VerifyResult>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    setError(undefined);
    try {
      setResult(await verifyAuditLog());
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return goToLogin();
      setError(err instanceof Error ? err.message : "verification failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="flex flex-wrap items-center gap-3">
        <Button tone="primary" onClick={run} disabled={busy}>
          {busy ? "Checking every entry…" : result ? "Check again" : "Check integrity"}
        </Button>
        {!result && !error && !compact ? (
          <span className="text-sm text-ink-2">
            Recomputes the hash of every entry and confirms each one still links to the one before.
          </span>
        ) : null}
      </div>

      {error ? (
        <p role="alert" className="mt-3 text-refused-ink">
          {error}
        </p>
      ) : null}

      {result ? (
        <div
          role="status"
          className={`mt-4 rounded border-l-4 px-4 py-3 ${
            result.valid ? "border-allowed bg-allowed-wash" : "border-refused bg-refused-wash"
          }`}
        >
          <ChainLinks result={result} />
          {result.valid ? (
            <>
              <p className="mt-2 font-display text-xl font-semibold text-allowed-ink">
                Intact: all {count(result.entry_count)} entries check out
              </p>
              <p className="mt-1 text-sm text-ink-2">
                Latest hash <code className="figures">{shortHash(result.head_hash)}…</code>. Note it down
                somewhere else: if a later check shows fewer entries, the newest ones were deleted.
              </p>
            </>
          ) : (
            <>
              <p className="mt-2 font-display text-xl font-semibold text-refused-ink">
                Tampered: entry #{result.first_broken_sequence} no longer matches
              </p>
              <p className="mt-1 text-sm text-ink">
                {result.reason}. The {count(result.entry_count)} entries before it check out; everything from
                #{result.first_broken_sequence} on can&apos;t be trusted.
              </p>
              {!compact ? null : (
                <Link href="/audit" className="mt-2 inline-block text-sm font-semibold underline underline-offset-2">
                  Open the audit log
                </Link>
              )}
            </>
          )}
        </div>
      ) : null}
    </div>
  );
}
