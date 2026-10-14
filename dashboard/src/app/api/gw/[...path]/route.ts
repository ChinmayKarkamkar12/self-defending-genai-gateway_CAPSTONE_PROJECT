// Forwards the dashboard's calls to the gateway's /v1/admin API with the
// admin session attached (backend-for-frontend). Only /v1/admin/* is
// reachable through here, never the chat endpoint.
import { NextResponse, type NextRequest } from "next/server";

import { GATEWAY_URL, SESSION_COOKIE, sameOrigin } from "@/lib/server/gateway";

const SAFE_SEGMENT = /^[A-Za-z0-9._:-]+$/;
// Response headers worth passing back (the CSV export needs the last two).
const PASS_HEADERS = ["content-type", "content-disposition"];

async function forward(request: NextRequest, ctx: RouteContext<"/api/gw/[...path]">) {
  const { path } = await ctx.params;
  if (path.some((segment) => !SAFE_SEGMENT.test(segment) || segment === "..")) {
    return NextResponse.json({ detail: "invalid path" }, { status: 400 });
  }
  if (request.method !== "GET" && !sameOrigin(request, request.nextUrl.origin)) {
    return NextResponse.json({ detail: "cross-site request refused" }, { status: 403 });
  }
  const token = request.cookies.get(SESSION_COOKIE)?.value;
  if (!token) {
    return NextResponse.json({ detail: "admin login required" }, { status: 401 });
  }

  const target = `${GATEWAY_URL}/v1/admin/${path.join("/")}${request.nextUrl.search}`;
  const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
  let body: string | undefined;
  if (request.method !== "GET") {
    body = await request.text();
    headers["Content-Type"] = "application/json";
  }

  let upstream: Response;
  try {
    upstream = await fetch(target, { method: request.method, headers, body, cache: "no-store" });
  } catch {
    return NextResponse.json({ detail: "the gateway is not reachable" }, { status: 502 });
  }

  const responseHeaders = new Headers();
  for (const name of PASS_HEADERS) {
    const value = upstream.headers.get(name);
    if (value) responseHeaders.set(name, value);
  }
  const response = new NextResponse(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });
  if (upstream.status === 401) {
    // Expired or logged out at the gateway: drop the dead cookie too.
    response.cookies.delete(SESSION_COOKIE);
  }
  return response;
}

export const GET = forward;
export const POST = forward;
export const PUT = forward;
