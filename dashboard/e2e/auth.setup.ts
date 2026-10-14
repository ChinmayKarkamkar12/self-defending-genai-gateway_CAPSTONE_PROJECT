// Logs in once through the real login form and saves the session cookie for
// the other tests.
import { expect, test as setup } from "@playwright/test";

setup("log in as the admin", async ({ page }) => {
  const user = process.env.E2E_ADMIN_USER;
  const password = process.env.E2E_ADMIN_PASSWORD;
  if (!user || !password) throw new Error("set E2E_ADMIN_USER and E2E_ADMIN_PASSWORD");

  await page.goto("/login");
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Today at the checkpoint" })).toBeVisible();
  await page.context().storageState({ path: "e2e/.auth/admin.json" });
});
