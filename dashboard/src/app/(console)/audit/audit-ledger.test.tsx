import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import { auditEntry } from "@/test/fixtures";
import { GW, server } from "@/test/server";
import { AuditLedger } from "./audit-ledger";

describe("Audit log", () => {
  it("lists entries newest first with plain-language outcomes", async () => {
    render(<AuditLedger />);
    expect(await screen.findByText("Blocked as an attack")).toBeInTheDocument();
    const rows = screen.getAllByRole("row");
    expect(rows[1]).toHaveTextContent("3");
    expect(screen.getAllByText("1 email addresses")).toHaveLength(2);
  });

  it("shows an entry's hashes on demand", async () => {
    render(<AuditLedger />);
    const [link] = await screen.findAllByRole("button", { name: /aaaaaaaaaa to bbbbbbbbbb/ });
    await userEvent.click(link);
    expect(screen.getByText("b".repeat(64))).toBeInTheDocument();
    expect(link).toHaveAttribute("aria-expanded", "true");
  });

  it("filters by outcome and covers the whole of the chosen days", async () => {
    let query: URLSearchParams | undefined;
    server.use(
      http.get(`${GW}/logs`, ({ request }) => {
        query = new URL(request.url).searchParams;
        return HttpResponse.json({ entries: [], next_before_sequence: null });
      }),
    );
    render(<AuditLedger />);
    await screen.findByText("No entries match these filters.");

    await userEvent.selectOptions(screen.getByLabelText("What happened"), "escalated");
    await userEvent.type(screen.getByLabelText("From"), "2026-10-13");
    await userEvent.type(screen.getByLabelText("To"), "2026-10-13");
    await userEvent.click(screen.getByRole("button", { name: "Show entries" }));

    await screen.findByText("No entries match these filters.");
    expect(query?.get("outcome")).toBe("escalated");
    expect(query?.get("from")).toBe("2026-10-13T00:00:00Z");
    expect(query?.get("to")).toBe("2026-10-13T23:59:59.999Z");
  });

  it("pages through older entries", async () => {
    server.use(
      http.get(`${GW}/logs`, ({ request }) => {
        const before = new URL(request.url).searchParams.get("before_sequence");
        return before
          ? HttpResponse.json({ entries: [auditEntry(1, { model: "older-model" })], next_before_sequence: null })
          : HttpResponse.json({ entries: [auditEntry(2)], next_before_sequence: 2 });
      }),
    );
    render(<AuditLedger />);
    await userEvent.click(await screen.findByRole("button", { name: "Show older entries" }));
    expect(await screen.findByText("older-model")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show older entries" })).not.toBeInTheDocument();
  });

  it("verifies the chain and reports it intact", async () => {
    render(<AuditLedger />);
    await userEvent.click(await screen.findByRole("button", { name: "Check integrity" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Intact: all 145 entries check out");
  });

  it("links the CSV export with the current filters", async () => {
    render(<AuditLedger />);
    expect(await screen.findByRole("link", { name: "Download CSV" })).toHaveAttribute(
      "href",
      "/api/gw/logs/export?format=csv",
    );
  });
});
