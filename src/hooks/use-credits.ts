import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { PLAN_LIMITS, scansRemaining, type Plan } from "@/lib/plan";

export function useCredits() {
  return useQuery({
    queryKey: ["credits"],
    queryFn: async () => {

      const { data: userData } = await supabase.auth.getUser();
      const user = userData.user;
      if (!user) return { plan: "free" as Plan, used: 0, limit: 1, remaining: 1 };

      const [{ data: profile }, { count }] = await Promise.all([
        supabase.from("profiles").select("plan").eq("id", user.id).maybeSingle(),
        supabase.from("assessments").select("id", { count: "exact", head: true }).eq("user_id", user.id),
      ]);

      const plan = ((profile?.plan as Plan) ?? "free") as Plan;
      const used = count ?? 0;
      const limit = PLAN_LIMITS[plan];
      return { plan, used, limit, remaining: scansRemaining(plan, used) };
    },
  });
}
