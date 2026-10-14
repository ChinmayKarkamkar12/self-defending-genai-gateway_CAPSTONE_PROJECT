// Name of the httpOnly cookie holding the admin session token. Shared by the
// server routes and proxy.ts (which can't import the server-only module).
export const SESSION_COOKIE = "gw_admin_session";
