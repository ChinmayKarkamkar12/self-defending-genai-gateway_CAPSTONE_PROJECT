import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it } from "vitest";

import { REVIEW_ITEM } from "@/test/fixtures";
import { GW, server } from "@/test/server";
import { stubNavigation } from "@/test/utils";
import { ReviewDesk } from "./review-desk";

describe("Review queue", () => {
  let nav: ReturnType<typeof stubNavigation> | undefined;
  afterEach(() => nav?.restore());

  it("shows the first waiting item with its redacted excerpt and scores", async () => {
    render(<ReviewDesk />);
    expect(await screen.findByRole("heading", { name: "Is this an attack?" })).toBeInTheDocument();
    expect(screen.getByText(REVIEW_ITEM.prompt_excerpt)).toBeInTheDocument();
    expect(screen.getByText("2 waiting")).toBeInTheDocument();
    expect(screen.getByText("0.64")).toBeInTheDocument();
  });

  it("deciding sends the verdict, reports the reward and moves to the next item", async () => {
    let decided: unknown;
    server.use(
      http.post(`${GW}/review-queue/:id/decide`, async ({ request, params }) => {
        decided = { id: params.id, body: await request.json() };
        return HttpResponse.json({
          item: { ...REVIEW_ITEM, status: "reviewed", decision: "attack" },
          reward_applied: 0.45,
          bandit_updated: true,
        });
      }),
    );
    render(<ReviewDesk />);
    await userEvent.click(await screen.findByRole("button", { name: "It's an attack" }));

    expect(decided).toEqual({ id: REVIEW_ITEM.id, body: { decision: "attack" } });
    expect(await screen.findByText(/Marked as an attack\. The defense learned from it \(reward \+0\.45\)/)).toBeInTheDocument();
    expect(screen.getByText("1 waiting")).toBeInTheDocument();
    expect(screen.queryByText(REVIEW_ITEM.prompt_excerpt)).not.toBeInTheDocument();
    expect(screen.getByText("user: Summarise this week's tickets")).toBeInTheDocument();
  });

  it("decides from the keyboard", async () => {
    render(<ReviewDesk />);
    await screen.findByRole("heading", { name: "Is this an attack?" });
    await userEvent.keyboard("s");
    expect(await screen.findByText(/Marked as safe/)).toBeInTheDocument();
  });

  it("says so when nothing is waiting", async () => {
    server.use(http.get(`${GW}/review-queue`, () => HttpResponse.json([])));
    render(<ReviewDesk />);
    expect(await screen.findByText(/Nothing is waiting for review/)).toBeInTheDocument();
  });

  it("shows the gateway's reason when a decision is refused", async () => {
    server.use(
      http.post(`${GW}/review-queue/:id/decide`, () =>
        HttpResponse.json({ detail: "review item expired" }, { status: 409 }),
      ),
    );
    render(<ReviewDesk />);
    await userEvent.click(await screen.findByRole("button", { name: "It's safe" }));
    expect(await screen.findByText("review item expired")).toBeInTheDocument();
  });

  it("sends an expired session back to the login page", async () => {
    nav = stubNavigation();
    server.use(http.get(`${GW}/review-queue`, () => HttpResponse.json({ detail: "x" }, { status: 401 })));
    render(<ReviewDesk />);
    await vi_waitFor(() => expect(nav!.assign).toHaveBeenCalledWith("/login?next=%2Freview"));
  });
});

async function vi_waitFor(check: () => void) {
  const { waitFor } = await import("@testing-library/react");
  await waitFor(check);
}
