export type Plan = "free" | "pro" | "business";

export const PLAN_LIMITS: Record<Plan, number> = {
  free: 1,
  pro: 5,
  business: Infinity,
};

export const PLAN_LABELS: Record<Plan, string> = {
  free: "Free",
  pro: "Pro",
  business: "Business",
};

export function scansRemaining(plan: Plan, used: number): number {
  const limit = PLAN_LIMITS[plan];
  if (limit === Infinity) return Infinity;
  return Math.max(0, limit - used);
}
