"use client";

import { useEffect } from "react";

import { getTeams } from "@/lib/api-client";
import type { Team, UUID } from "@/lib/types";
import { useGateway } from "@/lib/use-gateway";
import { Select } from "./ui";

/** Team names by ID, for screens that show team IDs. */
export function useTeams(): Map<UUID, string> {
  const teams = useGateway(getTeams, []);
  return new Map((teams.data ?? []).map((t: Team) => [t.id, t.name]));
}

export function TeamPicker({
  value,
  onChange,
  allowAll = false,
}: {
  value: UUID | undefined;
  onChange: (id: UUID | undefined) => void;
  allowAll?: boolean;
}) {
  const teams = useGateway(getTeams, []);

  // Screens that need one team start on the first.
  useEffect(() => {
    if (!allowAll && value === undefined && teams.data && teams.data.length > 0) {
      onChange(teams.data[0].id);
    }
  }, [allowAll, value, teams.data, onChange]);

  return (
    <Select
      label="Team"
      value={value ?? ""}
      onChange={(event) => onChange(event.target.value || undefined)}
      disabled={!teams.data}
    >
      {allowAll ? <option value="">All teams</option> : null}
      {(teams.data ?? []).map((team) => (
        <option key={team.id} value={team.id}>
          {team.name}
        </option>
      ))}
    </Select>
  );
}
