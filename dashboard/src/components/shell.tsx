"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";

import { getMe, logout } from "@/lib/api-client";
import { useGateway } from "@/lib/use-gateway";

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/review", label: "Review queue" },
  { href: "/audit", label: "Audit log" },
  { href: "/threats", label: "Threats" },
  { href: "/cost", label: "Cost & usage" },
  { href: "/pii", label: "Personal data" },
];

/** A barrier-arm gate: the gateway's mark. */
export function GateMark({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 40 24" aria-hidden className={className}>
      <rect x="2" y="6" width="5" height="16" rx="1" fill="currentColor" />
      <g transform="rotate(-8 7 9)">
        <rect x="7" y="6.5" width="31" height="5" rx="1" fill="#f5f7f9" stroke="currentColor" strokeWidth="1.2" />
        <rect x="12" y="6.5" width="4" height="5" fill="#a6243a" />
        <rect x="20" y="6.5" width="4" height="5" fill="#a6243a" />
        <rect x="28" y="6.5" width="4" height="5" fill="#a6243a" />
      </g>
    </svg>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const me = useGateway(getMe, []);
  const [leaving, setLeaving] = useState(false);

  async function signOut() {
    setLeaving(true);
    try {
      await logout();
    } finally {
      router.replace("/login");
      router.refresh();
    }
  }

  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-10 focus:bg-sheet focus:px-3 focus:py-2"
      >
        Skip to content
      </a>
      <header className="border-b border-rule bg-sheet">
        <div className="mx-auto flex max-w-[1240px] flex-wrap items-center gap-x-10 gap-y-2 px-6 pt-4">
          <Link href="/" className="flex items-center gap-2.5 pb-3 text-ink">
            <GateMark className="h-6 w-10" />
            <span className="font-display text-xl font-semibold">Gateway checkpoint</span>
          </Link>
          <nav aria-label="Main" className="order-3 -mb-px flex w-full gap-6 overflow-x-auto lg:order-none lg:w-auto">
            {NAV.map((item) => {
              const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  className={`whitespace-nowrap border-b-[3px] pb-3 pt-1 text-[0.95rem] font-semibold transition-colors ${
                    active
                      ? "border-ink text-ink"
                      : "border-transparent text-ink-2 hover:border-rule hover:text-ink"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
          <div className="ml-auto flex items-center gap-4 pb-3 text-sm text-ink-2">
            {me.data ? <span>Signed in as <strong className="text-ink">{me.data.username}</strong></span> : null}
            <button
              type="button"
              onClick={signOut}
              disabled={leaving}
              className="font-semibold text-ink underline-offset-4 hover:underline"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main id="main" className="mx-auto max-w-[1240px] px-6 pb-20 pt-10">
        {children}
      </main>
    </div>
  );
}
