import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { RiskPill, SeverityBadge } from "@/components/severity-badge";
import { Activity, AlertTriangle, ShieldCheck, TrendingUp, Plus, FileText } from "lucide-react";
import type { Severity } from "@/lib/scan";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({ meta: [{ title: "Dashboard — SentraX" }] }),
  component: Dashboard,
});

function Dashboard() {
  const q = useQuery({
    queryKey: ["dashboard"],
    queryFn: async () => {
      const [assessments, findings] = await Promise.all([
        supabase.from("assessments").select("id, security_score, risk_level, created_at, companies(company_name, website)").order("created_at", { ascending: false }).limit(5),
        supabase.from("findings").select("id, title, severity, created_at").order("created_at", { ascending: false }).limit(6),
      ]);
      return { assessments: assessments.data ?? [], findings: findings.data ?? [] };
    },
  });

  const latest = q.data?.assessments[0];
  const score = latest?.security_score ?? 0;
  const risk = latest?.risk_level ?? "Medium";

  return (
    <AppShell
      title="Security Overview"
      actions={
        <>
          <Button asChild variant="outline" size="sm"><Link to="/reports"><FileText className="mr-2 h-4 w-4" />Reports</Link></Button>
          <Button asChild size="sm" className="bg-gradient-primary text-primary-foreground shadow-glow">
            <Link to="/assessments/new"><Plus className="mr-2 h-4 w-4" />New Assessment</Link>
          </Button>
        </>
      }
    >
      <div className="grid gap-4 md:grid-cols-3">
        <Card className="col-span-1 border-border/60 bg-gradient-card p-6 md:col-span-1">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Security Score</span>
            <RiskPill risk={risk} />
          </div>
          <div className="mt-4 flex items-end gap-3">
            <div className="text-5xl font-bold text-gradient">{score}</div>
            <div className="pb-2 text-sm text-muted-foreground">/ 100</div>
          </div>
          <div className="mt-4 h-2 overflow-hidden rounded-full bg-muted">
            <div className="h-full bg-gradient-primary transition-all" style={{ width: `${score}%` }} />
          </div>
          {!latest && <p className="mt-4 text-sm text-muted-foreground">Run your first assessment to generate a score.</p>}
        </Card>

        <StatCard icon={Activity} label="Total Scans" value={q.data?.assessments.length ?? 0} tone="info" />
        <StatCard icon={AlertTriangle} label="Vulnerabilities Found" value={q.data?.findings.length ?? 0} tone="warning" />
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-3">
        <StatCard icon={ShieldCheck} label="Security Improvements" value={Math.max(0, (q.data?.findings.length ?? 0) - 2)} tone="success" />
        <StatCard icon={TrendingUp} label="Score Trend" value={latest ? "+8" : "—"} tone="primary" />
        <Card className="border-border/60 bg-gradient-card p-6">
          <div className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Quick Actions</div>
          <div className="mt-4 space-y-2">
            <Button asChild size="sm" className="w-full justify-start bg-gradient-primary text-primary-foreground"><Link to="/assessments/new"><Plus className="mr-2 h-4 w-4" />Start New Assessment</Link></Button>
            <Button asChild size="sm" variant="outline" className="w-full justify-start"><Link to="/reports"><FileText className="mr-2 h-4 w-4" />View Reports</Link></Button>
          </div>
        </Card>
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Card className="border-border/60 bg-gradient-card p-6">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="font-semibold">Recent Assessments</h2>
            <Link to="/reports" className="text-xs text-primary hover:underline">View all</Link>
          </div>
          <div className="space-y-2">
            {(q.data?.assessments ?? []).map((a) => (
              <Link key={a.id} to="/reports/$id" params={{ id: a.id }} className="flex items-center justify-between rounded-md border border-border/60 bg-background/40 p-3 transition-colors hover:bg-accent/50">
                <div className="min-w-0">
                  <div className="truncate font-medium">{a.companies?.company_name ?? "Untitled"}</div>
                  <div className="truncate font-mono text-xs text-muted-foreground">{a.companies?.website}</div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="font-mono text-sm">{a.security_score}</div>
                  <RiskPill risk={a.risk_level} />
                </div>
              </Link>
            ))}
            {(q.data?.assessments ?? []).length === 0 && (
              <p className="text-sm text-muted-foreground">No assessments yet.</p>
            )}
          </div>
        </Card>

        <Card className="border-border/60 bg-gradient-card p-6">
          <h2 className="mb-4 font-semibold">Recent Activity</h2>
          <div className="space-y-3">
            {(q.data?.findings ?? []).map((f) => (
              <div key={f.id} className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-sm">{f.title}</div>
                  <div className="font-mono text-xs text-muted-foreground">{new Date(f.created_at).toLocaleString()}</div>
                </div>
                <SeverityBadge severity={f.severity as Severity} />
              </div>
            ))}
            {(q.data?.findings ?? []).length === 0 && (
              <p className="text-sm text-muted-foreground">No findings yet.</p>
            )}
          </div>
        </Card>
      </div>
    </AppShell>
  );
}

function StatCard({ icon: Icon, label, value, tone }: { icon: React.ComponentType<{ className?: string }>; label: string; value: number | string; tone: "warning" | "success" | "info" | "primary" }) {
  const map = { warning: "text-warning", success: "text-success", info: "text-info", primary: "text-primary" } as const;
  return (
    <Card className="border-border/60 bg-gradient-card p-6">
      <div className="flex items-center justify-between">
        <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">{label}</span>
        <Icon className={`h-4 w-4 ${map[tone]}`} />
      </div>
      <div className="mt-3 text-3xl font-bold">{value}</div>
    </Card>
  );
}
