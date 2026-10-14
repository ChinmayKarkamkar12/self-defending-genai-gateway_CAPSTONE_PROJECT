"use client";

import { useState } from "react";

import { TeamPicker } from "@/components/team-picker";
import { Button, PageHeader, Status } from "@/components/ui";
import { ApiError, getRedactionEntities, getRedactionPolicy, putRedactionPolicy } from "@/lib/api-client";
import type { RedactionMode } from "@/lib/types";
import { goToLogin, useGateway } from "@/lib/use-gateway";
import { entityLabel } from "@/lib/vocabulary";

const EXAMPLE: Record<string, string> = {
  EMAIL_ADDRESS: "jane@example.com",
  PHONE_NUMBER: "415-555-0132",
  PERSON: "Jane Doe",
  CREDIT_CARD: "4111 1111 1111 1111",
  US_SSN: "123-45-6789",
  API_KEY: "sk-live-…",
  IP_ADDRESS: "192.168.0.12",
  LOCATION: "Paris",
  IBAN_CODE: "GB82 WEST 1234 …",
  US_PASSPORT: "912803456",
  US_DRIVER_LICENSE: "D1234567",
  US_BANK_NUMBER: "123456789012",
};

const MODES: { value: RedactionMode; title: string; body: string; sample: string }[] = [
  {
    value: "mask",
    title: "Mask",
    body: "Replaced with a label naming what was removed. The value is gone for good.",
    sample: "Email me at [REDACTED_EMAIL_ADDRESS]",
  },
  {
    value: "tokenize",
    title: "Tokenize",
    body: "Replaced with a unique token. The original is kept encrypted in the gateway's vault, so it can be traced later; it is never sent to the model.",
    sample: "Email me at [REDACTED_EMAIL_ADDRESS_3f9a1c2e]",
  },
];

export function PiiPolicyView() {
  const [teamId, setTeamId] = useState<string>();
  const entities = useGateway(getRedactionEntities, []);
  const policy = useGateway(teamId ? () => getRedactionPolicy(teamId) : null, [teamId]);
  // Kept here, not in the editor: saving reloads the policy and remounts it.
  const [notice, setNotice] = useState<string>();

  const usingDefaults = policy.error instanceof ApiError && policy.error.status === 404;
  const loadError = entities.error ?? (usingDefaults ? undefined : policy.error);
  // The team's own policy, or the gateway's defaults when it has none.
  const start =
    entities.data && teamId && !policy.loading
      ? policy.data && policy.data.team_id === teamId
        ? { enabled: policy.data.enabled_entities, mode: policy.data.mode, own: true }
        : usingDefaults
          ? { enabled: entities.data.default_enabled, mode: entities.data.default_mode, own: false }
          : undefined
      : undefined;

  return (
    <>
      <PageHeader
        title="Personal data"
        lead="What the gateway removes from prompts before they leave for a model provider. Only counts of what was removed are ever logged, never the values."
        actions={
          <TeamPicker
            value={teamId}
            onChange={(id) => {
              setTeamId(id);
              setNotice(undefined);
            }}
          />
        }
      />

      {notice ? (
        <p role="status" className="mb-6 rounded border-l-4 border-allowed bg-allowed-wash px-4 py-3 font-semibold text-allowed-ink">
          {notice}
        </p>
      ) : null}

      <Status
        loading={!start && !loadError}
        error={loadError}
        onRetry={() => {
          entities.reload();
          policy.reload();
        }}
      >
        {start && entities.data && teamId ? (
          <PolicyEditor
            // A fresh editor for each team and each saved version.
            key={`${teamId}:${start.own}:${start.mode}:${start.enabled.join(",")}`}
            teamId={teamId}
            supported={entities.data.supported}
            initialEnabled={start.enabled}
            initialMode={start.mode}
            usingDefaults={!start.own}
            onSaved={() => {
              setNotice("Policy saved. It applies to this team's next request.");
              policy.reload();
            }}
            onEdit={() => setNotice(undefined)}
          />
        ) : null}
      </Status>
    </>
  );
}

function PolicyEditor({
  teamId,
  supported,
  initialEnabled,
  initialMode,
  usingDefaults,
  onSaved,
  onEdit,
}: {
  teamId: string;
  supported: string[];
  initialEnabled: string[];
  initialMode: RedactionMode;
  usingDefaults: boolean;
  onSaved: () => void;
  onEdit: () => void;
}) {
  const [enabled, setEnabled] = useState<Set<string>>(() => new Set(initialEnabled));
  const [mode, setMode] = useState<RedactionMode>(initialMode);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  function toggle(entity: string) {
    setEnabled((current) => {
      const next = new Set(current);
      if (next.has(entity)) next.delete(entity);
      else next.add(entity);
      return next;
    });
    setError(undefined);
    onEdit();
  }

  async function save() {
    setBusy(true);
    try {
      await putRedactionPolicy(teamId, {
        enabled_entities: supported.filter((e) => enabled.has(e)),
        mode,
      });
      onSaved();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return goToLogin();
      setError(err instanceof Error ? err.message : "Couldn't save the policy.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {usingDefaults ? (
        <p className="mb-6 rounded border-l-4 border-rule bg-sheet px-4 py-3 text-ink-2">
          This team has no policy of its own and gets the gateway&apos;s defaults, shown below. Saving
          creates its own policy.
        </p>
      ) : null}

      <div className="grid gap-10 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <fieldset>
          <legend className="mb-3 w-full border-b border-rule pb-2 font-display text-xl font-semibold">
            Remove these
          </legend>
          <ul className="grid gap-x-6 sm:grid-cols-2">
            {supported.map((entity) => (
              <li key={entity} className="border-b border-rule-soft">
                <label className="flex cursor-pointer items-start gap-3 py-3">
                  <input
                    type="checkbox"
                    checked={enabled.has(entity)}
                    onChange={() => toggle(entity)}
                    className="mt-1 h-4 w-4 accent-ink"
                  />
                  <span>
                    <span className="block font-semibold">{entityLabel(entity)}</span>
                    <span className="block text-sm text-ink-3">for example {EXAMPLE[entity] ?? entity}</span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
        </fieldset>

        <fieldset>
          <legend className="mb-3 w-full border-b border-rule pb-2 font-display text-xl font-semibold">
            How to remove it
          </legend>
          <div className="space-y-3">
            {MODES.map((m) => (
              <label
                key={m.value}
                className={`block cursor-pointer rounded border px-4 py-3 ${
                  mode === m.value ? "border-ink bg-sheet" : "border-rule hover:border-ink-3"
                }`}
              >
                <span className="flex items-center gap-3">
                  <input
                    type="radio"
                    name="mode"
                    value={m.value}
                    checked={mode === m.value}
                    onChange={() => {
                      setMode(m.value);
                      setError(undefined);
                      onEdit();
                    }}
                    className="h-4 w-4 accent-ink"
                  />
                  <span className="font-display text-lg font-semibold">{m.title}</span>
                </span>
                <span className="mt-1 block text-sm text-ink-2">{m.body}</span>
                <code className="mt-2 block rounded bg-cleaned-wash px-2 py-1 text-sm text-cleaned-ink">
                  {m.sample}
                </code>
              </label>
            ))}
          </div>
        </fieldset>
      </div>

      <div className="mt-8 flex flex-wrap items-center gap-4 border-t border-rule pt-5">
        <Button tone="primary" onClick={save} disabled={busy}>
          {busy ? "Saving…" : "Save policy"}
        </Button>
        <span className="text-sm text-ink-2">
          {enabled.size} of {supported.length} kinds removed
        </span>
        {error ? (
          <span role="alert" className="text-sm font-semibold text-refused-ink">
            {error}
          </span>
        ) : null}
      </div>
    </>
  );
}
