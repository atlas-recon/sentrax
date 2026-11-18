import { createFileRoute, Link } from "@tanstack/react-router";
import {
  ShieldCheck, Activity, Radar, Lock, Cpu, FileText, ArrowRight, Check,
  Mail, Phone, MapPin, Instagram, Building2, Users, Clock,
} from "lucide-react";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Logo } from "@/components/logo";
import { SceneBackdrop } from "@/components/scene-backdrop";
import securityImage from "@/assets/section-security.jpg";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Shahin Security — Cybersecurity Risk Assessment for Business" },
      { name: "description", content: "Shahin Security is a business cybersecurity company. We assess your website security, report the risks in plain language, and help you fix them fast." },
      { property: "og:title", content: "Shahin Security — Cybersecurity Risk Assessment for Business" },
      { property: "og:description", content: "Website security assessments, executive reports and remediation guidance for growing companies." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Landing,
});

function Landing() {
  return (
    <div className="scene relative isolate min-h-screen text-foreground">
      <SceneBackdrop />
      <SiteHeader />

      {/* Hero */}
      <section className="border-b border-border">
        <div className="mx-auto grid min-h-[88vh] max-w-7xl items-center gap-12 px-4 py-20 sm:px-6 lg:grid-cols-2 lg:py-28">
          <div>
            <span className="inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 text-xs font-medium text-primary">
              <ShieldCheck className="h-3.5 w-3.5" /> Cybersecurity for growing businesses
            </span>
            <h1 className="mt-5 text-balance text-4xl font-bold leading-[1.05] tracking-tight sm:text-6xl">
              Know your cyber risk. <span className="text-gradient">Fix it with confidence.</span>
            </h1>
            <p className="mt-5 max-w-xl text-lg text-muted-foreground">
              Shahin Security assesses your website and online systems, explains every weakness in plain business
              language, and gives your team a clear plan to close the gaps.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Button asChild size="lg">
                <Link to="/auth" search={{ mode: "register" }}>
                  Request an assessment <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
              <Button asChild size="lg" variant="outline">
                <a href="#services">Our services</a>
              </Button>
            </div>
            <dl className="mt-10 grid max-w-lg grid-cols-3 gap-6 border-t border-border pt-6">
              {[["120+", "Assessments delivered"], ["<2 min", "Baseline scan time"], ["24/7", "Monitoring available"]].map(([v, l]) => (
                <div key={l}>
                  <dt className="text-2xl font-semibold text-primary">{v}</dt>
                  <dd className="mt-1 text-xs text-muted-foreground">{l}</dd>
                </div>
              ))}
            </dl>
          </div>
          <div className="hidden lg:block" />
        </div>
      </section>

      {/* Services */}
      <section id="services" className="mx-auto max-w-7xl px-4 py-20 sm:px-6">
        <SectionHeader eyebrow="Services" title="What we do for your business" subtitle="A complete security practice, delivered as a service and backed by our online assessment platform." />
        <div className="mt-12 grid gap-6 md:grid-cols-3">
          {[
            { icon: Radar, t: "Website Security Assessment", d: "Automated and manual review of your public web presence, mapped to the OWASP Top 10." },
            { icon: Lock, t: "SSL / TLS & Configuration", d: "Certificates, protocols, security headers, cookies and DNS/email protection reviewed end to end." },
            { icon: FileText, t: "Executive Reporting", d: "Board-ready PDF reports with an overall risk score, prioritised findings and remediation steps." },
            { icon: Cpu, t: "AI Risk Analysis", d: "Each finding is explained in business terms — what it means, what it costs, how to fix it." },
            { icon: Activity, t: "Continuous Monitoring", d: "Scheduled re-assessments so new weaknesses are caught as your site changes." },
            { icon: Users, t: "Advisory & Training", d: "Guidance for your developers and staff on secure practice and compliance readiness." },
          ].map((f) => (
            <Card key={f.t} className="border-border bg-card p-6 transition-shadow hover:shadow-elegant">
              <div className="mb-4 grid h-11 w-11 place-items-center rounded-md bg-primary/10 text-primary">
                <f.icon className="h-5 w-5" />
              </div>
              <h3 className="font-semibold">{f.t}</h3>
              <p className="mt-2 text-sm text-muted-foreground">{f.d}</p>
            </Card>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="border-y border-border bg-secondary/50">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6">
          <SectionHeader eyebrow="Process" title="How an assessment works" subtitle="From your web address to an actionable report — five clear steps." />
          <div className="mt-12 grid gap-4 md:grid-cols-5">
            {[
              { icon: Radar, t: "Website analysis", d: "We map your public surface." },
              { icon: Lock, t: "SSL / TLS check", d: "Certificates and encryption." },
              { icon: ShieldCheck, t: "Security headers", d: "Browser protections in place." },
              { icon: Cpu, t: "Technology review", d: "Frameworks and exposures." },
              { icon: Activity, t: "Risk evaluation", d: "Scored, prioritised, reported." },
            ].map((s, i) => (
              <Card key={s.t} className="border-border bg-card p-5">
                <div className="mb-3 flex items-center justify-between">
                  <s.icon className="h-5 w-5 text-primary" />
                  <span className="font-mono text-xs text-muted-foreground">0{i + 1}</span>
                </div>
                <div className="font-medium">{s.t}</div>
                <p className="mt-1 text-sm text-muted-foreground">{s.d}</p>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Why */}
      <section className="mx-auto max-w-7xl px-4 py-20 sm:px-6">
        <div className="grid items-center gap-12 lg:grid-cols-2">
          <img
            src={securityImage}
            alt="Secure data centre protected by encryption"
            loading="lazy"
            width={1408}
            height={1008}
            className="w-full rounded-xl border border-border object-cover shadow-elegant"
          />
          <div>
            <SectionHeader align="left" eyebrow="Why Shahin Security" title="Security that speaks business" subtitle="Most attacks succeed through weaknesses that are already known and fixable — if someone is looking." />
            <ul className="mt-8 space-y-3 text-sm">
              {[
                "43% of cyber attacks target small and mid-sized companies.",
                "The average breach costs millions in downtime and recovery.",
                "Reports written for executives, with detail your developers can act on.",
                "Supports readiness for SOC 2, ISO 27001 and client security reviews.",
              ].map((s) => (
                <li key={s} className="flex gap-3">
                  <Check className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                  <span className="text-muted-foreground">{s}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      {/* Scoring */}
      <section id="score" className="border-y border-border bg-secondary/50">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6">
          <SectionHeader eyebrow="Scoring" title="One number your board can follow" subtitle="Every assessment produces a security score from 0 to 100, tracked over time." />
          <div className="mt-12 grid items-center gap-10 md:grid-cols-2">
            <div className="flex justify-center"><ScoreOrb /></div>
            <div className="space-y-4">
              {[
                { r: "80 – 100", risk: "Low", tone: "text-success", d: "Mature posture, small backlog of low-severity items." },
                { r: "55 – 79", risk: "Medium", tone: "text-warning", d: "Meaningful weaknesses present, remediation should be scheduled." },
                { r: "0 – 54", risk: "High", tone: "text-destructive", d: "Immediate action required — exposure to common attacks." },
              ].map((row) => (
                <Card key={row.risk} className="flex items-center justify-between border-border bg-card p-4">
                  <div>
                    <div className={`font-semibold ${row.tone}`}>{row.risk} risk</div>
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
      <section id="pricing" className="mx-auto max-w-7xl px-4 py-20 sm:px-6">
        <SectionHeader eyebrow="Pricing" title="Simple, transparent plans" subtitle="Start with one free assessment. Upgrade as your coverage grows." />
        <div className="mt-12 grid gap-6 md:grid-cols-3">
          {[
            { name: "Starter", price: "$0", features: ["1 website assessment", "Full OWASP Top 10 report", "PDF export", "Basic recommendations"], cta: "Start free" },
            { name: "Professional", price: "$10", featured: true, features: ["5 websites", "Unlimited re-assessments", "AI recommendations", "Professional PDF reports", "Priority email support"], cta: "Choose Professional" },
            { name: "Enterprise", price: "$50", features: ["Unlimited websites", "Continuous monitoring", "Team dashboards", "Compliance support", "Priority support"], cta: "Talk to us" },
          ].map((p) => (
            <Card key={p.name} className={`relative border-border bg-card p-6 ${p.featured ? "border-primary shadow-elegant" : ""}`}>
              {p.featured && <span className="absolute -top-2.5 right-4 rounded-full bg-primary px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-primary-foreground">Most popular</span>}
              <div className="font-semibold">{p.name}</div>
              <div className="mt-2 text-3xl font-semibold">{p.price}<span className="text-sm font-normal text-muted-foreground">/month</span></div>
              <ul className="mt-5 space-y-2 text-sm">
                {p.features.map((f) => (
                  <li key={f} className="flex items-center gap-2 text-muted-foreground"><Check className="h-4 w-4 text-primary" />{f}</li>
                ))}
              </ul>
              <Button asChild className="mt-6 w-full" variant={p.featured ? "default" : "outline"}>
                {p.name === "Starter"
                  ? <Link to="/auth" search={{ mode: "register" }}>{p.cta}</Link>
                  : <Link to="/upgrade">{p.cta}</Link>}
              </Button>
            </Card>
          ))}
        </div>
      </section>

      {/* About */}
      <section id="about" className="border-y border-border bg-secondary/50">
        <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6">
          <div className="grid gap-12 lg:grid-cols-2">
            <div>
              <SectionHeader align="left" eyebrow="About us" title="A security company built for lean teams" subtitle="Shahin Security combines automated assessment technology with hands-on security expertise." />
              <p className="mt-6 text-muted-foreground">
                We work with small and mid-sized companies that depend on their website and online
                systems but do not have a full security department. Our platform runs the technical
                assessment; our analysts turn the results into decisions your business can act on.
                Every client gets the same standard of reporting a large enterprise would expect.
              </p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              {[
                { icon: Building2, t: "Business first", d: "Findings framed around revenue, trust and continuity." },
                { icon: ShieldCheck, t: "Standards based", d: "Aligned with OWASP, and supportive of ISO 27001 and SOC 2." },
                { icon: Clock, t: "Fast turnaround", d: "Baseline results in minutes, full report the same day." },
                { icon: Users, t: "Human support", d: "Real analysts available to walk your team through the report." },
              ].map((v) => (
                <Card key={v.t} className="border-border bg-card p-5">
                  <v.icon className="h-5 w-5 text-primary" />
                  <div className="mt-3 font-medium">{v.t}</div>
                  <p className="mt-1 text-sm text-muted-foreground">{v.d}</p>
                </Card>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Contact */}
      <section id="contact" className="mx-auto max-w-7xl px-4 py-20 sm:px-6">
        <div className="grid gap-10 lg:grid-cols-2">
          <div>
            <SectionHeader align="left" eyebrow="Contact" title="Talk to our team" subtitle="Tell us about your systems and we will recommend the right level of assessment." />
            <div className="mt-8 space-y-4 text-sm">
              <p className="flex items-center gap-3"><Phone className="h-4 w-4 text-primary" /> +255 773 841 274</p>
              <p className="flex items-center gap-3"><Mail className="h-4 w-4 text-primary" /> hello@sentrax.io</p>
              <p className="flex items-center gap-3"><MapPin className="h-4 w-4 text-primary" /> Dar es Salaam, Tanzania</p>
              <p className="flex items-center gap-3">
                <Instagram className="h-4 w-4 text-primary" />
                <a href="https://instagram.com/core.sec" target="_blank" rel="noreferrer" className="hover:text-primary">@core.sec</a>
              </p>
            </div>
            <p className="mt-6 text-xs text-muted-foreground">
              These contact details are placeholders except the phone number and Instagram — send me the
              real email and office address and I will update them.
            </p>
          </div>
          <Card className="border-border bg-card p-8">
            <h3 className="text-xl font-semibold">Start your first assessment free</h3>
            <p className="mt-2 text-sm text-muted-foreground">
              Create an account and run a full security assessment of one website at no cost — report included.
            </p>
            <Button asChild size="lg" className="mt-6">
              <Link to="/auth" search={{ mode: "register" }}>Create your free account</Link>
            </Button>
          </Card>
        </div>
      </section>

      <footer className="border-t border-border bg-navy/80 py-10 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-4 sm:flex-row sm:px-6">
          <Logo />
          <nav className="flex gap-6 text-sm text-muted-foreground">
            <a href="#services" className="hover:text-primary">Services</a>
            <a href="#pricing" className="hover:text-primary">Pricing</a>
            <Link to="/sponsors" className="hover:text-primary">Partners</Link>
            <a href="#contact" className="hover:text-primary">Contact</a>
          </nav>
          <p className="text-xs text-muted-foreground">© {new Date().getFullYear()} Shahin Security. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}

function SectionHeader({ eyebrow, title, subtitle, align = "center" }: { eyebrow: string; title: string; subtitle: string; align?: "center" | "left" }) {
  return (
    <div className={align === "center" ? "mx-auto max-w-2xl text-center" : "max-w-2xl"}>
      <div className="text-xs font-semibold uppercase tracking-widest text-primary">{eyebrow}</div>
      <h2 className="mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">{title}</h2>
      <p className="mt-3 text-muted-foreground">{subtitle}</p>
    </div>
  );
}

function ScoreOrb() {
  const size = 220;
  const stroke = 14;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const score = 85;
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke} className="stroke-muted" fill="none" />
        <circle cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke} strokeLinecap="round"
          className="stroke-primary" fill="none"
          strokeDasharray={c} strokeDashoffset={c - (c * score) / 100} />
      </svg>
      <div className="absolute grid place-items-center">
        <div className="text-5xl font-semibold">{score}</div>
        <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Security score</div>
      </div>
    </div>
  );
}
