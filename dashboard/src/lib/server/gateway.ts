import "server-only";

// Where the gateway is, from this app's server. Never sent to the browser.
export const GATEWAY_URL = (process.env.GATEWAY_URL ?? "http://localhost:8000").replace(/\/$/, "");

// The admin session token from the gateway's login is kept in an httpOnly
// cookie: the browser stores and sends it, but its JavaScript can't read it,
// so a script injected into the page can't steal the session.
export { SESSION_COOKIE } from "@/lib/session-cookie";

// Non-GET requests must come from this app's own pages. SameSite=Strict on
// the cookie already stops other sites' forms from carrying it; this is the
// second check. It compares the browser's Origin with the Host it asked for,
// not with the server's own idea of its address: in Docker the server binds
// 0.0.0.0:3000 while the browser is on localhost:3000.
export function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (origin === null) return true; // not a browser cross-site request
  const host = request.headers.get("host");
  try {
    return host !== null && new URL(origin).host === host;
  } catch {
    return false;
  }
}
