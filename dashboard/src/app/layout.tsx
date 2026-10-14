import type { Metadata } from "next";
import { Atkinson_Hyperlegible_Next, Barlow_Semi_Condensed } from "next/font/google";

import "./globals.css";

const body = Atkinson_Hyperlegible_Next({
  subsets: ["latin"],
  variable: "--font-body",
  display: "swap",
  // Next has no metrics to size-match a fallback for this family.
  adjustFontFallback: false,
  fallback: ["system-ui", "sans-serif"],
});

const sign = Barlow_Semi_Condensed({
  subsets: ["latin"],
  weight: ["500", "600", "700"],
  variable: "--font-sign",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Gateway checkpoint",
  description: "Admin console for the Self-Defending GenAI Gateway",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${body.variable} ${sign.variable}`}>
      <body>{children}</body>
    </html>
  );
}
