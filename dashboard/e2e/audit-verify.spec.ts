// Full stack, nothing mocked: the browser asks the dashboard, the dashboard
// asks the gateway, the gateway re-hashes every audit entry in Postgres.
import { expect, test } from "@playwright/test";

test("verify integrity shows an intact chain", async ({ page }) => {
  await page.goto("/audit");
  await expect(page.getByRole("heading", { name: "Audit log" })).toBeVisible();
  // The ledger shows real entries from the gateway.
  await expect(page.getByRole("row").nth(1)).toBeVisible();

  await page.getByRole("button", { name: "Check integrity" }).click();
  const result = page.getByRole("status");
  await expect(result).toContainText(/Intact: all [\d,]+ entries check out/);
});

test("the overview draws the route from live data", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("img", { name: "Route through the checkpoint" })).toBeVisible();
  await expect(page.getByText("Requests", { exact: true })).toBeVisible();
});
