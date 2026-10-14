import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import { EMPTY_OVERVIEW, VERIFY_BROKEN } from "@/test/fixtures";
import { GW, server } from "@/test/server";
import { OverviewView } from "./overview-view";

describe("Overview", () => {
  it("shows the route and the figures from the gateway", async () => {
    render(<OverviewView />);

    const route = await screen.findByRole("img", { name: /route through the checkpoint/i });
    // The accessible description reads the whole route out.
    // One of the 100 hit an internal error, which isn't tied to a stage.
    expect(route).toHaveAccessibleDescription(/99 requests entered/);
    expect(route).toHaveAccessibleDescription(/1 internal errors are not on the route/);
    expect(route).toHaveAccessibleDescription(/Screening: 8 stopped/);
    expect(route).toHaveAccessibleDescription(/80 answered/);

    const figures = screen.getByText("Requests").closest("dl")!;
    expect(within(figures).getByText("100")).toBeInTheDocument();
    expect(within(figures).getByText("Waiting for review").nextSibling).toHaveTextContent("2");
    expect(within(figures).getByRole("link", { name: "Review now" })).toHaveAttribute("href", "/review");
    expect(screen.getByText("Email addresses")).toBeInTheDocument();
  });

  it("shows a loading state first", () => {
    render(<OverviewView />);
    expect(screen.getAllByText("Loading…").length).toBeGreaterThan(0);
  });

  it("explains a failure and offers a retry", async () => {
    server.use(
      http.get(`${GW}/stats/overview`, () => HttpResponse.json({ detail: "database down" }, { status: 503 })),
    );
    render(<OverviewView />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load this: database down");
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("handles a window with no traffic", async () => {
    server.use(
      http.get(`${GW}/stats/overview`, () => HttpResponse.json(EMPTY_OVERVIEW)),
      http.get(`${GW}/stats/timeline`, () =>
        HttpResponse.json({ window_from: "", window_to: "", bucket: "day", buckets: [] }),
      ),
    );
    render(<OverviewView />);
    expect(await screen.findByText("No requests in this window yet.")).toBeInTheDocument();
    expect(screen.getByText("None found in this window.")).toBeInTheDocument();
  });

  it("reloads for another time window", async () => {
    const seen: string[] = [];
    server.use(
      http.get(`${GW}/stats/overview`, ({ request }) => {
        seen.push(new URL(request.url).searchParams.get("from") ?? "");
        return HttpResponse.json(EMPTY_OVERVIEW);
      }),
    );
    render(<OverviewView />);
    await screen.findByRole("img", { name: /route/i });
    await userEvent.click(screen.getByRole("radio", { name: "30 days" }));
    expect(await screen.findByRole("heading", { name: "The last 30 days" })).toBeInTheDocument();
    expect(seen).toHaveLength(2);
    expect(new Date(seen[1]).getTime()).toBeLessThan(new Date(seen[0]).getTime());
  });

  it("reports a tampered audit log prominently", async () => {
    server.use(http.get(`${GW}/logs/verify`, () => HttpResponse.json(VERIFY_BROKEN)));
    render(<OverviewView />);
    await userEvent.click(await screen.findByRole("button", { name: "Check integrity" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Tampered: entry #2 no longer matches");
    expect(screen.getByRole("status")).toHaveTextContent("Its contents were changed after it was written. The 1 entry before it checks out");
  });
});
