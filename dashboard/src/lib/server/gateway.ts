import "server-only";

// Where the gateway is, from this app's server. Never sent to the browser.
export const GATEWAY_URL = (process.env.GATEWAY_URL ?? "http://localhost:8000").replace(/\/$/, "");

// The admin session token from the gateway's login is kept in an httpOnly
// cookie: the browser stores and sends it, but its JavaScript can't read it,
// so a script injected into the page can't steal the session.
export { SESSION_COOKIE } from "@/lib/session-cookie";

// Non-GET requests must come from this app's own pages. SameSite=Strict on
// the cookie already stops other sites' forms from carrying it; this is the
// second check.
export function sameOrigin(request: Request, ownOrigin: string): boolean {
  const origin = request.headers.get("origin");
  return origin === null || origin === ownOrigin;
}
