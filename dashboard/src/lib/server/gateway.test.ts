import { describe, expect, it } from "vitest";

import { sameOrigin } from "./gateway";

function req(headers: Record<string, string>) {
  return new Request("http://0.0.0.0:3000/api/auth/login", { method: "POST", headers });
}

describe("sameOrigin", () => {
  it("accepts the browser's own origin even when the server binds 0.0.0.0", () => {
    expect(sameOrigin(req({ origin: "http://localhost:3000", host: "localhost:3000" }))).toBe(true);
  });

  it("refuses another site", () => {
    expect(sameOrigin(req({ origin: "http://evil.example", host: "localhost:3000" }))).toBe(false);
  });

  it("refuses a different port on the same host", () => {
    expect(sameOrigin(req({ origin: "http://localhost:8080", host: "localhost:3000" }))).toBe(false);
  });

  it("refuses a malformed origin", () => {
    expect(sameOrigin(req({ origin: "null", host: "localhost:3000" }))).toBe(false);
  });

  it("allows requests without an Origin header (not cross-site browser requests)", () => {
    expect(sameOrigin(req({ host: "localhost:3000" }))).toBe(true);
  });
});
