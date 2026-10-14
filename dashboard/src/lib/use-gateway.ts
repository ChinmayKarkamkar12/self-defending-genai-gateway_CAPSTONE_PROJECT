"use client";

import { useCallback, useEffect, useState } from "react";

import { ApiError } from "./api-client";

export interface Loaded<T> {
  data: T | undefined;
  error: ApiError | Error | undefined;
  loading: boolean;
  reload: () => void;
}

export function goToLogin(): void {
  const next = window.location.pathname;
  window.location.assign(next === "/" ? "/login" : `/login?next=${encodeURIComponent(next)}`);
}

interface Settled<T> {
  key: string;
  data?: T;
  error?: ApiError | Error;
}

/**
 * Loads data with `load` whenever `deps` change; the previous data stays on
 * screen while the next load runs. A 401 (session expired or logged out
 * elsewhere) sends the browser to the login page. `load` = null means
 * "nothing to load yet" (e.g. no team picked).
 */
export function useGateway<T>(load: (() => Promise<T>) | null, deps: unknown[]): Loaded<T> {
  const [tick, setTick] = useState(0);
  const [settled, setSettled] = useState<Settled<T>>({ key: "" });
  const key = JSON.stringify([...deps, tick, load === null]);

  useEffect(() => {
    if (load === null) return;
    let cancelled = false;
    load().then(
      (data) => {
        if (!cancelled) setSettled({ key, data });
      },
      (err: unknown) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 401) {
          goToLogin();
          return;
        }
        setSettled((prev) => ({
          key,
          data: prev.data,
          error: err instanceof Error ? err : new Error(String(err)),
        }));
      },
    );
    return () => {
      cancelled = true;
    };
    // `load` is recreated every render; `key` captures what it depends on.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  const current = settled.key === key;
  return {
    data: settled.data,
    error: current ? settled.error : undefined,
    loading: load !== null && !current,
    reload,
  };
}
