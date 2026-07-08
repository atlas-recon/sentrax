import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { AppShell } from "@/components/app-shell";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { RiskPill, SeverityBadge } from "@/components/severity-badge";
import { Download, ArrowLeft } from "lucide-react";
import { toast } from "sonner";
import type { Severity } from "@/lib/scan";

export const Route = createFileRoute("/_authenticated/reports/$id")({
  head: () => ({ meta: [{ title: "Report — SentraX" }] }),
  component: ReportDetail,
});

function ReportDetail() {
  const { id } = Route.useParams();
  const q = useQuery({
    queryKey: ["report", id],
    queryFn: async () => {
      const [assessment, findings] = await Promise.all([
        supabase.from("assessments").select("id, security_score, risk_level, created_at, companies(company_name, website)").eq("id", id).single(),
        supabase.from("findings").select("*").eq("assessment_id", id).order("severity"),
      ]);
      return { a: assessment.data, findings: findings.data ?? [] };
    },
  });

  const a = q.data?.a;
  const findings = q.data?.findings ?? [];

  return (
    <AppShell title="Security Report"
      actions={
        <>
          <Button asChild variant="outline" size="sm"><Link to="/reports"><ArrowLeft className="mr-2 h-4 w-4" />All reports</Link></Button>
          <Button size="sm" className="bg-gradient-primary text-primary-foreground" onClick={() => toast.info("PDF export coming soon")}>
            <Download className="mr-2 h-4 w-4" />Download
          </Button>
        </>
      }>
      {!a ? (
        <Card className="border-border/60 bg-gradient-card p-8 text-center text-muted-foreground">Loading…</Card>
      ) : (
        <div className="space-y-6">
          <Card className="border-border/60 bg-gradient-card p-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="font-mono text-xs uppercase tracking-widest text-primary">Executive Summary</div>
                <h2 className="mt-1 text-2xl font-semibold">{a.companies?.company_name}</h2>
                <div className="font-mono text-sm text-muted-foreground">{a.companies?.website}</div>
                <div className="mt-1 text-xs text-muted-foreground">Generated {new Date(a.created_at).toLocaleString()}</div>
              </div>
              <div className="text-right">
                <div className="text-5xl font-bold text-gradient">{a.security_score}<span className="text-lg text-muted-foreground">/100</span></div>
                <div className="mt-2"><RiskPill risk={a.risk_level} /></div>
              </div>
            </div>
            <p className="mt-6 text-sm text-muted-foreground">
              SentraX identified {findings.length} finding{findings.length === 1 ? "" : "s"} across your public attack surface. Overall posture is rated <strong className="text-foreground">{a.risk_level}</strong>. Prioritize the high-severity items below within the next 30 days to materially reduce risk.
            </p>
          </Card>

          <Card className="border-border/60 bg-gradient-card p-6">
            <h3 className="mb-4 font-semibold">Findings</h3>
            <div className="space-y-4">
              {findings.map((f) => (
                <div key={f.id} className="rounded-lg border border-border/60 bg-background/40 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="font-medium">{f.title}</div>
                    <SeverityBadge severity={f.severity as Severity} />
                  </div>
                  <div className="mt-3 grid gap-3 md:grid-cols-2">
                    <div>
                      <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Impact</div>
                      <p className="mt-1 text-sm text-muted-foreground">{f.description}</p>
                    </div>
                    <div>
                      <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Recommendation</div>
                      <p className="mt-1 text-sm">{f.recommendation}</p>
                    </div>
                  </div>
                </div>
              ))}
              {findings.length === 0 && <p className="text-sm text-muted-foreground">No findings recorded.</p>}
            </div>
          </Card>
        </div>
      )}
    </AppShell>
  );
}
