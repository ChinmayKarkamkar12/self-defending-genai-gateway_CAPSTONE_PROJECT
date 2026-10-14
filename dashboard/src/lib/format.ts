const integer = new Intl.NumberFormat("en-US");

export function count(value: number): string {
  return integer.format(value);
}

// Costs are tiny per request, so show enough places to see them.
export function money(value: string | number): string {
  const amount = typeof value === "string" ? Number(value) : value;
  if (amount === 0) return "$0";
  if (Math.abs(amount) < 0.01) return `$${amount.toFixed(6).replace(/0+$/, "")}`;
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(amount);
}

export function percent(part: number, whole: number): string {
  if (whole === 0) return "0%";
  const value = (part / whole) * 100;
  return `${value < 10 && value > 0 ? value.toFixed(1) : Math.round(value)}%`;
}

export function dateTime(iso: string): string {
  return new Date(iso).toLocaleString("en-GB", {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function shortDate(iso: string, bucket: "hour" | "day" = "day"): string {
  const date = new Date(iso);
  return bucket === "hour"
    ? date.toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit" })
    : date.toLocaleDateString("en-GB", { day: "numeric", month: "short" });
}

export function shortHash(hash: string): string {
  return hash.slice(0, 10);
}

export function probability(value: number): string {
  return value.toFixed(2);
}

// Window presets used across screens, as ISO strings for the API.
export type WindowKey = "today" | "7d" | "30d";

export function windowRange(key: WindowKey, now = new Date()): { from: string; to: string } {
  const to = now.toISOString();
  if (key === "today") {
    const start = new Date(now);
    start.setUTCHours(0, 0, 0, 0);
    return { from: start.toISOString(), to };
  }
  const days = key === "7d" ? 7 : 30;
  return { from: new Date(now.getTime() - days * 86_400_000).toISOString(), to };
}
