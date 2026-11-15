import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { PLAN_LIMITS, scansRemaining, usagePeriodStart, type Plan } from "@/lib/plan";

export function useCredits() {
  return useQuery({
    queryKey: ["credits"],
    queryFn: async () => {
      const { data: userData } = await supabase.auth.getUser();
      const user = userData.user;
      if (!user) return { plan: "free" as Plan, used: 0, limit: 1, remaining: 1 };
      const { data: profile } = await supabase.from("profiles").select("plan").eq("id", user.id).maybeSingle();
      const plan = ((profile?.plan as Plan) ?? "free") as Plan;
      let q = supabase.from("assessments").select("id", { count: "exact", head: true }).eq("user_id", user.id);
      const since = usagePeriodStart(plan);
      if (since) q = q.gte("created_at", since);
      const { count } = await q;
      const used = count ?? 0;
      return { plan, used, limit: PLAN_LIMITS[plan], remaining: scansRemaining(plan, used) };
    },
  });
}

export function useIsAdmin() {
  return useQuery({
    queryKey: ["is-admin"],
    queryFn: async () => {
      const { data: userData } = await supabase.auth.getUser();
      if (!userData.user) return false;
      const { data } = await supabase.rpc("has_role", { _user_id: userData.user.id, _role: "admin" });
      return !!data;
    },
  });
}
