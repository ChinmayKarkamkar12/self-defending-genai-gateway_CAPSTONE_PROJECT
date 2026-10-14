import { vi } from "vitest";

/** jsdom can't navigate; record where the app tried to send the browser. */
export function stubNavigation() {
  const assign = vi.fn();
  const original = window.location;
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { ...original, assign, pathname: "/review", search: "", origin: original.origin },
  });
  return {
    assign,
    restore: () => Object.defineProperty(window, "location", { configurable: true, value: original }),
  };
}
