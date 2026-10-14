import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  resolve: {
    tsconfigPaths: true,
    // `server-only` throws outside a server build; the server modules are
    // still worth unit-testing.
    alias: { "server-only": new URL("./src/test/server-only-stub.ts", import.meta.url).pathname },
  },
  test: {
    environment: "jsdom",
    environmentOptions: { jsdom: { url: "http://localhost:3000/" } },
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    // The default process pool times out starting jsdom workers on Windows.
    pool: "threads",
  },
});
