import { describe, it, expect } from "vitest";
import { PLAN_LIMITS, PLAN_PRICES_TZS, scansRemaining, usagePeriodStart } from "./plan";

describe("plans", () => {
  it("prices in TSh", () => {
    expect(PLAN_PRICES_TZS.pro).toBe(15000);
    expect(PLAN_PRICES_TZS.business).toBe(45000);
  });
  it("free gets 1 scan total", () => {
    expect(PLAN_LIMITS.free).toBe(1);
    expect(scansRemaining("free", 1)).toBe(0);
    expect(usagePeriodStart("free")).toBeNull();
  });
  it("pro gets 20 per month, business unlimited", () => {
    expect(scansRemaining("pro", 5)).toBe(15);
    expect(usagePeriodStart("pro", new Date("2026-11-15T10:00:00Z"))).toBe("2026-11-01T00:00:00.000Z");
    expect(scansRemaining("business", 999)).toBe(Infinity);
  });
});
