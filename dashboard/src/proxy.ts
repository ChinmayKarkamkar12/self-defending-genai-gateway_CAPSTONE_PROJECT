// Sends anyone without a session cookie to the login page. This is only the
// quick, optimistic check: the gateway validates the session on every call,
// and an expired one sends the page back here (see useGateway).
import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE } from "@/lib/session-cookie";

export function proxy(request: NextRequest) {
  if (!request.cookies.has(SESSION_COOKIE)) {
    const login = new URL("/login", request.url);
    if (request.nextUrl.pathname !== "/") {
      login.searchParams.set("next", request.nextUrl.pathname);
    }
    return NextResponse.redirect(login);
  }
  return NextResponse.next();
}

export const config = {
  // Every page except the login page, Next's own files and the API routes
  // (which answer 401 themselves rather than redirecting).
  matcher: ["/((?!login|api|_next/static|_next/image|favicon.ico|.*\.svg$).*)"],
};
