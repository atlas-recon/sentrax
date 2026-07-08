import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { AppShell } from "@/components/app-shell";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { RiskPill } from "@/components/severity-badge";
import { FileText, Plus } from "lucide-react";

export const Route = createFileRoute("/_authenticated/reports/")({
  head: () => ({ meta: [{ title: "Reports — SentraX" }] }),
  component: ReportsList,
});

function ReportsList() {
  const q = useQuery({
    queryKey: ["reports"],
    queryFn: async () => {
      const { data } = await supabase.from("assessments")
        .select("id, security_score, risk_level, created_at, companies(company_name, website)")
        .order("created_at", { ascending: false });
      return data ?? [];
    },
  });
  return (
    <AppShell title="Security Reports"
      actions={<Button asChild size="sm" className="bg-gradient-primary text-primary-foreground"><Link to="/assessments/new"><Plus className="mr-2 h-4 w-4" />New Assessment</Link></Button>}>
      <Card className="border-border/60 bg-gradient-card p-0 overflow-hidden">
        <div className="hidden grid-cols-[1fr_1fr_auto_auto_auto] items-center gap-4 border-b border-border/60 p-4 font-mono text-[10px] uppercase tracking-widest text-muted-foreground md:grid">
          <div>Company</div><div>Website</div><div>Score</div><div>Risk</div><div>Date</div>
        </div>
        {(q.data ?? []).map((a) => (
          <Link key={a.id} to="/reports/$id" params={{ id: a.id }}
            className="grid grid-cols-2 items-center gap-3 border-b border-border/60 p-4 transition-colors hover:bg-accent/40 md:grid-cols-[1fr_1fr_auto_auto_auto] md:gap-4">
            <div className="min-w-0 truncate font-medium">{a.companies?.company_name}</div>
            <div className="min-w-0 truncate font-mono text-xs text-muted-foreground">{a.companies?.website}</div>
            <div className="font-mono">{a.security_score}</div>
            <RiskPill risk={a.risk_level} />
            <div className="col-span-2 text-xs text-muted-foreground md:col-span-1">{new Date(a.created_at).toLocaleDateString()}</div>
          </Link>
        ))}
        {(q.data ?? []).length === 0 && (
          <div className="p-10 text-center">
            <FileText className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">No reports yet. Run an assessment to generate one.</p>
          </div>
        )}
      </Card>
    </AppShell>
  );
}
