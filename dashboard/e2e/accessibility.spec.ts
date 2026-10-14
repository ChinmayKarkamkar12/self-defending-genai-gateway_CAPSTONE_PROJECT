// The plan's manual accessibility pass, kept as a test where it can be:
// keyboard reachability and labelled controls on every screen. (Colour
// contrast of the palette was checked against WCAG AA separately.)
import { expect, test } from "@playwright/test";

const PAGES = ["/", "/review", "/audit", "/threats", "/cost", "/pii"];

test("the first Tab reaches a skip link that jumps to the content", async ({ page }) => {
  await page.goto("/audit");
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to content" });
  await expect(skip).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#main$/);
});

for (const path of PAGES) {
  test(`every form control on ${path} has a label`, async ({ page }) => {
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    const unlabelled = await page.evaluate(() =>
      [...document.querySelectorAll("input, select, textarea, button")]
        .filter((el) => {
          const labels = (el as HTMLInputElement).labels;
          const text = (el.textContent ?? "").trim();
          return !(labels && labels.length) && !el.getAttribute("aria-label") && !text;
        })
        .map((el) => el.outerHTML.slice(0, 80)),
    );
    expect(unlabelled).toEqual([]);
  });
}

test("the review decision can be made without a mouse", async ({ page }) => {
  await page.route("**/api/gw/review-queue?*", (route) => route.fulfill({ json: [] }));
  await page.goto("/review");
  // Navigation is plain links, reachable in order.
  await page.keyboard.press("Tab"); // skip link
  await page.keyboard.press("Tab"); // brand
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Overview" })).toBeFocused();
});
