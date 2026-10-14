// Threats, cost and personal-data screens.
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { describe, expect, it } from "vitest";

import { TEAM } from "@/test/fixtures";
import { GW, server } from "@/test/server";
import { CostView } from "./cost/cost-view";
import { PiiPolicyView } from "./pii/pii-policy-view";
import { ThreatsView } from "./threats/threats-view";

describe("Threats", () => {
  it("summarises the defense's choices and learning", async () => {
    render(<ThreatsView />);
    expect(await screen.findByText("Block: 7")).toBeInTheDocument();
    expect(screen.getByText("62 decisions")).toBeInTheDocument();
    expect(screen.getByText("0.70")).toBeInTheDocument(); // mean reward
  });

  it("opens a session's risk trend and unlocks a locked key", async () => {
    let unlocked: string | undefined;
    server.use(
      http.get(`${GW}/sessions/:id/risk-trend`, () =>
        HttpResponse.json({
          session_id: "s-locked",
          team_id: TEAM.id,
          api_key_id: "key-1",
          requests: [
            {
              at: "2026-10-14T09:00:00Z",
              attack_probability: 0.9,
              action: "block",
              outcome: "block",
              escalation_bias: 0.5,
              forced_escalation: false,
            },
          ],
          policy_runs: [],
          live: { active: true, escalation_bias: 1, challenge_pending: false, locked: true },
        }),
      ),
      http.post(`${GW}/sessions/unlock/:key`, ({ params }) => {
        unlocked = String(params.key);
        return HttpResponse.json({ api_key_id: params.key, was_locked: true });
      }),
    );
    render(<ThreatsView />);
    await userEvent.click(await screen.findByRole("button", { name: /14 Oct/ }));
    expect(await screen.findByText("1 requests in this session")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Unlock key" }));
    expect(await screen.findByText(/Unlocked\. The key can send requests again\./)).toBeInTheDocument();
    expect(unlocked).toBe("key-1");
  });

  it("explains an empty learning history", async () => {
    server.use(
      http.get(`${GW}/bandit/stats`, () =>
        HttpResponse.json({
          window_from: "",
          window_to: "",
          model_version: 0,
          updates_per_action: {},
          pending_reviews: 0,
          action_counts: {},
          timeline: [],
          reward_trend: [],
          cumulative_reward: 0,
          mean_reward: null,
        }),
      ),
    );
    render(<ThreatsView />);
    expect(await screen.findByText(/No verdicts yet/)).toBeInTheDocument();
    expect(screen.getByText("No screened requests in this window.")).toBeInTheDocument();
  });
});

describe("Cost & usage", () => {
  it("shows spend against the budget for the first team", async () => {
    render(<CostView />);
    expect(await screen.findByRole("meter", { name: "Spend against budget" })).toHaveAttribute(
      "aria-valuenow",
      "8.5",
    );
    expect(screen.getByText(/\$1\.50 left today/)).toBeInTheDocument();
    expect(await screen.findByText("gpt-4o")).toBeInTheDocument();
  });

  it("explains a team with no budget, and sets one", async () => {
    let saved: unknown;
    server.use(
      http.get(`${GW}/budget/:team`, () =>
        HttpResponse.json({ detail: "no budget policy configured for this team" }, { status: 404 }),
      ),
      http.put(`${GW}/budget/:team`, async ({ request }) => {
        saved = await request.json();
        return HttpResponse.json({});
      }),
    );
    render(<CostView />);
    expect(await screen.findByText(/No budget set for this team/)).toBeInTheDocument();
    const limit = screen.getByLabelText("Limit in USD");
    await userEvent.clear(limit);
    await userEvent.type(limit, "25");
    await userEvent.click(screen.getByRole("button", { name: "Set budget" }));
    expect(await screen.findByText("Budget saved.")).toBeInTheDocument();
    expect(saved).toEqual({ period: "daily", limit_usd: "25", rate_limit_rps: 10 });
  });
});

describe("Personal data", () => {
  it("starts from the team's own policy and saves changes", async () => {
    let saved: JsonBodyType | undefined;
    server.use(
      http.put(`${GW}/redaction-policy/:team`, async ({ request }) => {
        saved = (await request.json()) as JsonBodyType;
        return HttpResponse.json(saved);
      }),
    );
    render(<PiiPolicyView />);
    const email = await screen.findByRole("checkbox", { name: /Email addresses/ });
    expect(email).toBeChecked();
    expect(screen.getByRole("checkbox", { name: /Phone numbers/ })).not.toBeChecked();
    expect(screen.getByRole("radio", { name: /Tokenize/ })).toBeChecked();

    await userEvent.click(screen.getByRole("checkbox", { name: /Places/ }));
    await userEvent.click(screen.getByRole("radio", { name: /Mask/ }));
    await userEvent.click(screen.getByRole("button", { name: "Save policy" }));
    expect(await screen.findByText(/Policy saved/)).toBeInTheDocument();
    expect(saved).toEqual({ enabled_entities: ["EMAIL_ADDRESS", "LOCATION"], mode: "mask" });
  });

  it("shows the gateway's defaults when the team has no policy", async () => {
    server.use(
      http.get(`${GW}/redaction-policy/:team`, () =>
        HttpResponse.json({ detail: "no redaction policy configured for this team" }, { status: 404 }),
      ),
    );
    render(<PiiPolicyView />);
    expect(await screen.findByText(/no policy of its own/)).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: /People's names/ })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: /Places/ })).not.toBeChecked();
    expect(screen.getByRole("radio", { name: /Mask/ })).toBeChecked();
  });
});
