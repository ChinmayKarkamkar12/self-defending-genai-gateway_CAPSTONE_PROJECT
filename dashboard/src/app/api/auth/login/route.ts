import { NextResponse, type NextRequest } from "next/server";

import { GATEWAY_URL, SESSION_COOKIE, sameOrigin } from "@/lib/server/gateway";

export async function POST(request: NextRequest) {
  if (!sameOrigin(request)) {
    return NextResponse.json({ detail: "cross-site request refused" }, { status: 403 });
  }
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: "send username and password as JSON" }, { status: 400 });
  }

  let upstream: Response;
  try {
    upstream = await fetch(`${GATEWAY_URL}/v1/admin/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      cache: "no-store",
    });
  } catch {
    return NextResponse.json({ detail: "the gateway is not reachable" }, { status: 502 });
  }
  const data = await upstream.json().catch(() => ({}));
  if (!upstream.ok) {
    return NextResponse.json(
      { detail: data?.detail ?? "login failed" },
      { status: upstream.status },
    );
  }

  // The token goes into the cookie only; the page gets just the username.
  const response = NextResponse.json({ username: data.username });
  response.cookies.set(SESSION_COOKIE, data.token, {
    httpOnly: true,
    sameSite: "strict",
    secure: request.nextUrl.protocol === "https:",
    path: "/",
    expires: new Date(data.expires_at),
  });
  return response;
}
