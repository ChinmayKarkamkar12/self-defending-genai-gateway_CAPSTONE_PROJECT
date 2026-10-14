import { expect, test } from "@playwright/test";

test.describe("without a session", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test("pages send you to the login page and back afterwards", async ({ page }) => {
    await page.goto("/audit");
    await expect(page).toHaveURL(/\/login\?next=%2Faudit$/);
  });

  test("a wrong password is refused with a plain message", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Username").fill("nobody-e2e");
    await page.getByLabel("Password").fill("definitely wrong");
    await page.getByRole("button", { name: "Sign in" }).click();
    // Next adds its own (empty) role="alert" route announcer to every page.
    await expect(page.getByRole("alert").filter({ hasText: "Wrong" })).toHaveText("Wrong username or password.");
  });

  test("the gateway API is not reachable without logging in", async ({ request }) => {
    const response = await request.get("/api/gw/logs/verify");
    expect(response.status()).toBe(401);
  });
});

test("the session cookie is invisible to page scripts", async ({ page, context }) => {
  await page.goto("/");
  const cookie = (await context.cookies()).find((c) => c.name === "gw_admin_session");
  expect(cookie?.httpOnly).toBe(true);
  expect(cookie?.sameSite).toBe("Strict");
  expect(await page.evaluate(() => document.cookie)).not.toContain("gw_admin_session");
});
