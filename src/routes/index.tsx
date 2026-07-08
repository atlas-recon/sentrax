import { createFileRoute, Link } from "@tanstack/react-router";
import { ShieldCheck, Activity, Radar, Zap, Lock, Cpu, TrendingUp, AlertTriangle, ArrowRight, Check } from "lucide-react";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Logo } from "@/components/logo";

export const Route = createFileRoute("/")({
  component: Landing,
});

function Landing() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <SiteHeader />

      {/* Hero */}
      <section className="relative overflow-hidden bg-hero">
        <div className="absolute inset-0 grid-bg opacity-40" />
        <div className="relative mx-auto max-w-7xl px-4 py-24 sm:px-6 sm:py-32">
          <div className="mx-auto max-w-3xl text-center">
            <div className="mx-auto mb-6 inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-xs font-medium text-primary">
              <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse-glow" />
              AI-powered threat intelligence
            </div>
            <h1 className="text-balance text-4xl font-bold leading-tight tracking-tight sm:text-6xl">
              See Your Cyber Risk <span className="text-gradient">Before Attackers Do</span>
            </h1>
            <p className="mx-auto mt-6 max-w-2xl text-balance text-lg text-muted-foreground">
              SentraX helps businesses analyze their security posture, identify risks, and receive actionable security recommendations — in minutes, not weeks.
            </p>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
              <Button asChild size="lg" className="bg-gradient-primary text-primary-foreground shadow-glow">
                <Link to="/auth" search={{ mode: "register" }}>
                  Start Security Assessment <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
              <Button asChild size="lg" variant="outline">
                <Link to="/dashboard">Explore Dashboard</Link>
              </Button>
            </div>
          </div>

          {/* Preview panel */}
          <div className="relative mx-auto mt-16 max-w-5xl">
            <div className="absolute -inset-4 rounded-2xl bg-primary/20 blur-3xl" />
            <Card className="relative overflow-hidden border-border/60 bg-gradient-card p-6 shadow-elegant">
              <div className="flex items-center justify-between border-b border-border/60 pb-4">
                <div className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-destructive/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-warning/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-success/70" />
                  <span className="ml-3 font-mono text-xs text-muted-foreground">sentrax.io/soc</span>
                </div>
                <span className="font-mono text-xs text-primary">LIVE</span>
              </div>
              <div className="grid gap-4 pt-6 md:grid-cols-3">
                <ScoreOrb />
                <div className="md:col-span-2 grid gap-3 sm:grid-cols-2">
                  <MiniStat icon={AlertTriangle} label="Open findings" value="12" tone="warning" />
                  <MiniStat icon={ShieldCheck} label="Patched this week" value="27" tone="success" />
                  <MiniStat icon={Activity} label="Scans (7d)" value="146" tone="info" />
                  <MiniStat icon={TrendingUp} label="Score trend" value="+8" tone="primary" />
                </div>
              </div>
            </Card>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="mx-auto max-w-7xl px-4 py-24 sm:px-6">
        <SectionHeader eyebrow="Workflow" title="How SentraX Works" subtitle="From URL to actionable report in five steps." />
        <div className="mt-12 grid gap-4 md:grid-cols-5">
          {[
            { icon: Radar, t: "Website Analysis" },
            { icon: Lock, t: "SSL / TLS Check" },
            { icon: ShieldCheck, t: "Security Headers" },
            { icon: Cpu, t: "Technology Detection" },
            { icon: Activity, t: "Risk Evaluation" },
          ].map((s, i) => (
            <Card key={s.t} className="relative border-border/60 bg-gradient-card p-5">
              <div className="mb-3 flex items-center justify-between">
                <s.icon className="h-5 w-5 text-primary" />
                <span className="font-mono text-xs text-muted-foreground">0{i + 1}</span>
              </div>
              <div className="font-semibold">{s.t}</div>
            </Card>
          ))}
        </div>
      </section>

      {/* Features */}
      <section id="features" className="border-y border-border/60 bg-card/40">
        <div className="mx-auto max-w-7xl px-4 py-24 sm:px-6">
          <SectionHeader eyebrow="Platform" title="Enterprise-grade features" subtitle="Everything your team needs to reduce risk continuously." />
          <div className="mt-12 grid gap-5 md:grid-cols-3">
            {[
              { icon: Radar, t: "Continuous Discovery", d: "Automated scans surface new attack surface as you ship." },
              { icon: Cpu, t: "AI Risk Analysis", d: "LLM-assisted triage explains impact and next steps in plain English." },
              { icon: ShieldCheck, t: "Actionable Reports", d: "Executive-ready PDFs and technical detail for engineers." },
              { icon: Lock, t: "SSL / TLS Insights", d: "Certificate chain, cipher and protocol posture at a glance." },
              { icon: Zap, t: "Fast Assessments", d: "Full baseline scan in under two minutes." },
              { icon: Activity, t: "SOC Dashboard", d: "Track your security score and trends over time." },
            ].map((f) => (
              <Card key={f.t} className="border-border/60 bg-gradient-card p-6 transition-all hover:shadow-glow">
                <div className="mb-4 grid h-10 w-10 place-items-center rounded-lg bg-primary/15 text-primary">
                  <f.icon className="h-5 w-5" />
                </div>
                <div className="font-semibold">{f.t}</div>
                <p className="mt-1 text-sm text-muted-foreground">{f.d}</p>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Why */}
      <section className="mx-auto max-w-7xl px-4 py-24 sm:px-6">
        <div className="grid items-center gap-12 md:grid-cols-2">
          <div>
            <SectionHeader align="left" eyebrow="Why now" title="Why Businesses Need Cybersecurity" subtitle="Small and mid-sized companies are the primary target of modern attackers." />
            <ul className="mt-8 space-y-3 text-sm">
              {[
                "43% of cyber attacks target small businesses.",
                "The average breach costs $4.45M in downtime and remediation.",
                "Most exploited weaknesses are known and fixable — if you can see them.",
                "Compliance frameworks (SOC 2, ISO 27001) require continuous monitoring.",
              ].map((s) => (
                <li key={s} className="flex gap-3">
                  <Check className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                  <span className="text-muted-foreground">{s}</span>
                </li>
              ))}
            </ul>
          </div>
          <Card className="border-border/60 bg-gradient-card p-8 shadow-elegant">
            <div className="mb-6 flex items-center justify-between">
              <span className="font-mono text-xs text-muted-foreground">RISK TIMELINE</span>
              <span className="font-mono text-xs text-primary">▲ Improving</span>
            </div>
            <div className="space-y-4">
              {[["Jan", 62], ["Feb", 68], ["Mar", 71], ["Apr", 76], ["May", 82], ["Jun", 85]].map(([m, v]) => (
                <div key={m as string} className="flex items-center gap-3">
                  <span className="w-8 font-mono text-xs text-muted-foreground">{m}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
                    <div className="h-full bg-gradient-primary" style={{ width: `${v}%` }} />
                  </div>
                  <span className="w-8 text-right font-mono text-xs">{v}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </section>

      {/* Security score */}
      <section id="score" className="border-y border-border/60 bg-card/40">
        <div className="mx-auto max-w-7xl px-4 py-24 sm:px-6">
          <SectionHeader eyebrow="Scoring" title="Understand your Security Score" subtitle="A single number that captures your posture across five domains." />
          <div className="mt-12 grid items-center gap-10 md:grid-cols-2">
            <div className="flex justify-center"><ScoreOrb big /></div>
            <div className="space-y-4">
              {[
                { r: "80 – 100", risk: "Low", tone: "text-success", d: "Mature posture, small backlog of low-severity items." },
                { r: "55 – 79", risk: "Medium", tone: "text-warning", d: "Meaningful weaknesses present, remediation should be scheduled." },
                { r: "0 – 54", risk: "High", tone: "text-destructive", d: "Immediate action required — active exposure to common attacks." },
              ].map((row) => (
                <Card key={row.risk} className="flex items-center justify-between border-border/60 bg-gradient-card p-4">
                  <div>
                    <div className={`font-semibold ${row.tone}`}>{row.risk} Risk</div>
                    <div className="text-sm text-muted-foreground">{row.d}</div>
                  </div>
                  <span className="font-mono text-sm text-muted-foreground">{row.r}</span>
                </Card>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="mx-auto max-w-7xl px-4 py-24 sm:px-6">
        <SectionHeader eyebrow="Pricing" title="Simple, transparent pricing" subtitle="Start free. Upgrade when you're ready to scale coverage." />
        <div className="mt-12 grid gap-5 md:grid-cols-3">
          {[
            { name: "Starter", price: "$0", features: ["1 domain", "Monthly scans", "Basic reports"], cta: "Start free" },
            { name: "Growth", price: "$49", featured: true, features: ["10 domains", "Weekly scans", "AI recommendations", "PDF exports"], cta: "Start 14-day trial" },
            { name: "Enterprise", price: "Custom", features: ["Unlimited domains", "Continuous scans", "SSO / SAML", "Priority support"], cta: "Contact sales" },
          ].map((p) => (
            <Card key={p.name} className={`relative border-border/60 bg-gradient-card p-6 ${p.featured ? "shadow-glow ring-1 ring-primary/50" : ""}`}>
              {p.featured && <span className="absolute -top-2 right-4 rounded-full bg-primary px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-primary-foreground">Popular</span>}
              <div className="font-semibold">{p.name}</div>
              <div className="mt-2 text-3xl font-bold">{p.price}<span className="text-sm font-normal text-muted-foreground">{p.price !== "Custom" && "/mo"}</span></div>
              <ul className="mt-5 space-y-2 text-sm">
                {p.features.map((f) => (
                  <li key={f} className="flex items-center gap-2 text-muted-foreground"><Check className="h-4 w-4 text-primary" />{f}</li>
                ))}
              </ul>
              <Button asChild className="mt-6 w-full" variant={p.featured ? "default" : "outline"}>
                <Link to="/auth" search={{ mode: "register" }}>{p.cta}</Link>
              </Button>
            </Card>
          ))}
        </div>
      </section>

      {/* About */}
      <section id="about" className="border-t border-border/60 bg-card/40">
        <div className="mx-auto max-w-3xl px-4 py-24 text-center sm:px-6">
          <SectionHeader eyebrow="About" title="Built for the defenders" subtitle="SentraX combines automated scanning, threat intelligence and AI reasoning to give lean security teams the visibility of a full SOC." />
          <div className="mt-8">
            <Button asChild size="lg" className="bg-gradient-primary text-primary-foreground shadow-glow">
              <Link to="/auth" search={{ mode: "register" }}>Create your free account</Link>
            </Button>
          </div>
        </div>
      </section>

      <footer className="border-t border-border/60 py-10">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-4 sm:flex-row sm:px-6">
          <Logo />
          <p className="text-xs text-muted-foreground">© {new Date().getFullYear()} SentraX. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}

function SectionHeader({ eyebrow, title, subtitle, align = "center" }: { eyebrow: string; title: string; subtitle: string; align?: "center" | "left" }) {
  return (
    <div className={align === "center" ? "mx-auto max-w-2xl text-center" : "max-w-2xl"}>
      <div className="font-mono text-xs uppercase tracking-widest text-primary">{eyebrow}</div>
      <h2 className="mt-2 text-3xl font-bold tracking-tight sm:text-4xl">{title}</h2>
      <p className="mt-3 text-muted-foreground">{subtitle}</p>
    </div>
  );
}

function MiniStat({ icon: Icon, label, value, tone }: { icon: React.ComponentType<{ className?: string }>; label: string; value: string; tone: "warning" | "success" | "info" | "primary" }) {
  const map = { warning: "text-warning", success: "text-success", info: "text-info", primary: "text-primary" } as const;
  return (
    <div className="rounded-lg border border-border/60 bg-background/40 p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">{label}</span>
        <Icon className={`h-4 w-4 ${map[tone]}`} />
      </div>
      <div className="mt-2 text-2xl font-bold">{value}</div>
    </div>
  );
}

function ScoreOrb({ big = false }: { big?: boolean }) {
  const size = big ? 240 : 160;
  const stroke = big ? 14 : 10;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const score = 85;
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke} className="stroke-muted" fill="none" />
        <circle cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke} strokeLinecap="round"
          className="stroke-primary drop-shadow-[0_0_10px_var(--color-primary)]" fill="none"
          strokeDasharray={c} strokeDashoffset={c - (c * score) / 100} />
      </svg>
      <div className="absolute grid place-items-center">
        <div className={big ? "text-5xl font-bold" : "text-3xl font-bold"}>{score}</div>
        <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Security score</div>
      </div>
    </div>
  );
}
