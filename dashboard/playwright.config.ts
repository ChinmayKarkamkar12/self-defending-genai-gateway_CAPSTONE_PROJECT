// End-to-end tests against a running stack: `docker compose up -d` from the
// repo root (dashboard on :3000, gateway behind it), and an admin account
// (`docker compose exec gateway python -m scripts.create_admin <name>`).
// Credentials come from the environment, never from the repo:
//   E2E_ADMIN_USER=... E2E_ADMIN_PASSWORD=... npm run test:e2e
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    trace: "retain-on-failure",
  },
  projects: [
    { name: "setup", testMatch: /auth\.setup\.ts/ },
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], storageState: "e2e/.auth/admin.json" },
      dependencies: ["setup"],
    },
  ],
});
