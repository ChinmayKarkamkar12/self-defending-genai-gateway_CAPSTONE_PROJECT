"use client";

import { useState, type FormEvent } from "react";

import { GateMark } from "@/components/shell";
import { ApiError, login } from "@/lib/api-client";

function nextPath(): string {
  const next = new URLSearchParams(window.location.search).get("next");
  // Only paths on this site, never an absolute URL somewhere else.
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
}

export function LoginForm() {
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError(undefined);
    try {
      await login(String(form.get("username")), String(form.get("password")));
      window.location.assign(nextPath());
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError("Too many wrong passwords for this username. Wait 15 minutes, then try again.");
      } else if (err instanceof ApiError && err.status === 401) {
        setError("Wrong username or password.");
      } else {
        setError(err instanceof Error ? err.message : "Sign-in failed.");
      }
      setBusy(false);
    }
  }

  return (
    <main className="grid min-h-screen place-items-center px-6 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex items-center gap-3 text-ink">
          <GateMark className="h-8 w-14" />
          <span className="font-display text-2xl font-semibold">Gateway checkpoint</span>
        </div>
        <form onSubmit={onSubmit} className="rounded border border-rule bg-sheet p-6" noValidate>
          <h1 className="text-2xl font-semibold">Sign in</h1>
          <p className="mt-1 text-ink-2">Administrators only. Every request through the gateway is visible here.</p>

          <label className="mt-6 block text-sm font-semibold" htmlFor="username">
            Username
          </label>
          <input
            id="username"
            name="username"
            autoComplete="username"
            required
            className="mt-1 min-h-11 w-full rounded border border-rule bg-sheet px-3 text-base"
          />

          <label className="mt-4 block text-sm font-semibold" htmlFor="password">
            Password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            className="mt-1 min-h-11 w-full rounded border border-rule bg-sheet px-3 text-base"
          />

          {error ? (
            <p role="alert" className="mt-4 rounded bg-refused-wash px-3 py-2 text-sm text-refused-ink">
              {error}
            </p>
          ) : null}

          <button
            type="submit"
            disabled={busy}
            className="mt-6 min-h-11 w-full rounded bg-ink font-semibold text-white hover:bg-[#21385a] disabled:bg-ink-3"
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
        <p className="mt-4 text-sm text-ink-3">
          No account? An administrator creates one on the gateway with
          <code className="mx-1 rounded bg-surface px-1">scripts.create_admin</code>.
        </p>
      </div>
    </main>
  );
}
