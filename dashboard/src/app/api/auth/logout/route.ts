import { NextResponse, type NextRequest } from "next/server";

import { GATEWAY_URL, SESSION_COOKIE, sameOrigin } from "@/lib/server/gateway";

export async function POST(request: NextRequest) {
  if (!sameOrigin(request)) {
    return NextResponse.json({ detail: "cross-site request refused" }, { status: 403 });
  }
  const token = request.cookies.get(SESSION_COOKIE)?.value;
  if (token) {
    // Ends the session at the gateway too, so the token is dead even if the
    // cookie was copied somewhere. Best effort: the cookie goes regardless.
    await fetch(`${GATEWAY_URL}/v1/admin/auth/logout`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    }).catch(() => undefined);
  }
  const response = new NextResponse(null, { status: 204 });
  response.cookies.delete(SESSION_COOKIE);
  return response;
}
