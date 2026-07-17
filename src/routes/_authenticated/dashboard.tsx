import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { RiskPill, SeverityBadge } from "@/components/severity-badge";
import { Activity, AlertTriangle, ShieldCheck, TrendingUp, Plus, FileText } from "lucide-react";
import type { Severity } from "@/lib/scan";
import { ScanCreditsCard } from "@/components/scan-credits";
import { VulnExplainer } from "@/components/vuln-explainer";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({ meta: [{ title: "Dashboard — SentraX" }] }),
  component: Dashboard,
});

const SEV_TONES: Record<Severity, string> = {
  critical: "#991b1b", high: "#dc2626", medium: "#d97706", low: "#2563eb", info: "#64748b",
};

function Dashboard() {
  const q = useQuery({
    queryKey: ["dashboard"],
    queryFn: async () => {
      const [assessments, findings] = await Promise.all([
        supabase.from("assessments").select("id, security_score, risk_level, created_at, companies(company_name, website)").order("created_at", { ascending: false }).limit(20),
        supabase.from("findings").select("id, title, severity, created_at").order("created_at", { ascending: false }).limit(50),
      ]);
      return { assessments: assessments.data ?? [], findings: findings.data ?? [] };
    },
  });

  const assessments = q.data?.assessments ?? [];
  const findings = q.data?.findings ?? [];
  const latest = assessments[0];
  const score = latest?.security_score ?? 0;
  const risk = latest?.risk_level ?? "Medium";

  const trend = [...assessments].reverse().slice(-8);
  const counts = findings.reduce(
    (acc, f) => { acc[f.severity as Severity] = (acc[f.severity as Severity] ?? 0) + 1; return acc; },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>,
  );

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
        <Card className="border-border/60 bg-gradient-card p-6">
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

        <ScanCreditsCard />
        <StatCard icon={AlertTriangle} label="Vulnerabilities" value={findings.length} tone="warning" />
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-4">
        <StatCard icon={Activity} label="Total Scans" value={assessments.length} tone="info" />
        <StatCard icon={ShieldCheck} label="Critical + High" value={counts.critical + counts.high} tone="success" />
        <StatCard icon={TrendingUp} label="Score Trend" value={trendDelta(trend)} tone="primary" />
        <Card className="border-border/60 bg-gradient-card p-6">
          <div className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Quick Actions</div>
          <div className="mt-4 space-y-2">
            <Button asChild size="sm" className="w-full justify-start bg-gradient-primary text-primary-foreground"><Link to="/assessments/new"><Plus className="mr-2 h-4 w-4" />Start New Assessment</Link></Button>
            <Button asChild size="sm" variant="outline" className="w-full justify-start"><Link to="/reports"><FileText className="mr-2 h-4 w-4" />View Reports</Link></Button>
          </div>
        </Card>
      </div>

      {/* Charts */}
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card className="border-border/60 bg-gradient-card p-6">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="font-semibold">Score Trend</h2>
            <span className="font-mono text-xs text-muted-foreground">Last {trend.length} scans</span>
          </div>
          <TrendChart data={trend.map((a) => ({ score: a.security_score, label: new Date(a.created_at).toLocaleDateString() }))} />
        </Card>

        <Card className="border-border/60 bg-gradient-card p-6">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="font-semibold">Findings by Severity</h2>
            <span className="font-mono text-xs text-muted-foreground">{findings.length} total</span>
          </div>
          <div className="space-y-2.5">
            {(["critical", "high", "medium", "low", "info"] as Severity[]).map((sev) => {
              const max = Math.max(1, ...Object.values(counts));
              return (
                <div key={sev} className="flex items-center gap-2">
                  <span className="w-16 font-mono text-[10px] uppercase" style={{ color: SEV_TONES[sev] }}>{sev}</span>
                  <div className="h-3 flex-1 overflow-hidden rounded-full bg-muted">
                    <div className="h-full rounded-full transition-all" style={{ width: `${(counts[sev] / max) * 100}%`, background: SEV_TONES[sev] }} />
                  </div>
                  <span className="w-8 text-right font-mono text-xs">{counts[sev]}</span>
                </div>
              );
            })}
          </div>
        </Card>
      </div>

      <div className="mt-4">
        <VulnExplainer findingTitles={findings.map((f) => f.title)} />
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Card className="border-border/60 bg-gradient-card p-6">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="font-semibold">Recent Assessments</h2>
            <Link to="/reports" className="text-xs text-primary hover:underline">View all</Link>
          </div>
          <div className="space-y-2">
            {assessments.slice(0, 5).map((a) => (
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
            {assessments.length === 0 && <p className="text-sm text-muted-foreground">No assessments yet.</p>}
          </div>
        </Card>

        <Card className="border-border/60 bg-gradient-card p-6">
          <h2 className="mb-4 font-semibold">Recent Activity</h2>
          <div className="space-y-3">
            {findings.slice(0, 8).map((f) => (
              <div key={f.id} className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-sm">{f.title}</div>
                  <div className="font-mono text-xs text-muted-foreground">{new Date(f.created_at).toLocaleString()}</div>
                </div>
                <SeverityBadge severity={f.severity as Severity} />
              </div>
            ))}
            {findings.length === 0 && <p className="text-sm text-muted-foreground">No findings yet.</p>}
          </div>
        </Card>
      </div>
    </AppShell>
  );
}

function trendDelta(trend: { security_score: number }[]) {
  if (trend.length < 2) return "—";
  const d = trend[trend.length - 1].security_score - trend[0].security_score;
  return (d >= 0 ? "+" : "") + d;
}

function TrendChart({ data }: { data: { score: number; label: string }[] }) {
  if (data.length === 0) return <p className="text-sm text-muted-foreground">Run scans to see the trend.</p>;
  const w = 500; const h = 160; const pad = 24;
  const xs = (i: number) => pad + (i / Math.max(1, data.length - 1)) * (w - pad * 2);
  const ys = (v: number) => h - pad - (v / 100) * (h - pad * 2);
  const path = data.map((d, i) => `${i === 0 ? "M" : "L"} ${xs(i)} ${ys(d.score)}`).join(" ");
  const area = `${path} L ${xs(data.length - 1)} ${h - pad} L ${xs(0)} ${h - pad} Z`;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full">
      <defs>
        <linearGradient id="areaFill" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity="0.35" />
          <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0, 25, 50, 75, 100].map((v) => (
        <line key={v} x1={pad} x2={w - pad} y1={ys(v)} y2={ys(v)} stroke="hsl(var(--border))" strokeDasharray="3 3" opacity="0.4" />
      ))}
      <path d={area} fill="url(#areaFill)" />
      <path d={path} fill="none" stroke="hsl(var(--primary))" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
      {data.map((d, i) => (
        <circle key={i} cx={xs(i)} cy={ys(d.score)} r="3.5" fill="hsl(var(--primary))" />
      ))}
    </svg>
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
