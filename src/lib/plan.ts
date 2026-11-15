export type Plan = "free" | "pro" | "business";

/** Free = lifetime total. Paid plans = per calendar month. */
export const PLAN_LIMITS: Record<Plan, number> = {
  free: 1,
  pro: 20,
  business: Infinity,
};

export const PLAN_LABELS: Record<Plan, string> = {
  free: "Starter",
  pro: "Professional",
  business: "Business",
};

export const PLAN_PRICES_TZS: Record<Plan, number> = {
  free: 0,
  pro: 15000,
  business: 45000,
};

export const PLAN_FEATURES: Record<Plan, { aiExplain: boolean; fullEvidence: boolean; pdf: boolean }> = {
  free: { aiExplain: false, fullEvidence: false, pdf: true },
  pro: { aiExplain: true, fullEvidence: true, pdf: true },
  business: { aiExplain: true, fullEvidence: true, pdf: true },
};

export function formatTzs(n: number): string {
  return n === 0 ? "TSh 0" : "TSh " + n.toLocaleString("en-US");
}

export function usagePeriodStart(plan: Plan, now = new Date()): string | null {
  if (plan === "free") return null;
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString();
}

export function scansRemaining(plan: Plan, used: number): number {
  const limit = PLAN_LIMITS[plan];
  if (limit === Infinity) return Infinity;
  return Math.max(0, limit - used);
}
