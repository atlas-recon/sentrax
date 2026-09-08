import { createFileRoute, Link } from "@tanstack/react-router";
import coreSecLogo from "@/assets/coresec-logo.png";
import { SiteHeader } from "@/components/site-header";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowRight, ShieldCheck, Cpu, Cloud, Code2, Instagram, Handshake, GraduationCap, Search } from "lucide-react";

export const Route = createFileRoute("/sponsors")({
  head: () => ({
    meta: [
      { title: "Partners — SentraX" },
      { name: "description", content: "SentraX partners with CoreSec, a cybersecurity engineering studio delivering secure development, AI defence and cloud protection." },
      { property: "og:title", content: "Partners — SentraX" },
      { property: "og:description", content: "Meet CoreSec, the cybersecurity engineering studio behind the SentraX assessment engine." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: SponsorsPage,
});

function SponsorsPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <SiteHeader />

      <section className="border-b border-border bg-hero">
        <div className="mx-auto max-w-4xl px-4 py-20 text-center sm:px-6">
          <span className="inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 text-xs font-medium text-primary">
            <Handshake className="h-3.5 w-3.5" /> Partnership
          </span>
          <h1 className="mt-5 text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
            In partnership with <span className="text-primary">CoreSec</span>
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-muted-foreground">
            CoreSec is a cybersecurity engineering studio. Their research team builds and maintains the
            detection logic behind the SentraX assessment engine, and their consultants support our
            clients on complex remediation work.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
        <Card className="overflow-hidden border-border bg-card p-8 shadow-elegant">
          <div className="grid items-center gap-10 md:grid-cols-2">
            <img
              src={coreSecLogo}
              alt="CoreSec — Secure Today, Protect Tomorrow"
              loading="lazy"
              className="mx-auto w-full max-w-sm rounded-lg"
            />
            <div>
              <p className="text-xs font-semibold uppercase tracking-widest text-primary">Principal partner</p>
              <h2 className="mt-2 text-3xl font-semibold">CoreSec</h2>
              <p className="mt-1 text-sm italic text-muted-foreground">Secure Today, Protect Tomorrow.</p>
              <p className="mt-4 text-muted-foreground">
                Founded by offensive-security practitioners, CoreSec works with businesses across East
                Africa on penetration testing, secure software delivery, cloud hardening and AI-driven
                defence. The partnership gives SentraX clients direct access to that expertise whenever a
                finding needs deeper investigation.
              </p>
              <div className="mt-6 flex flex-wrap gap-3">
                <Button asChild>
                  <a href="https://instagram.com/core.sec" target="_blank" rel="noreferrer">
                    <Instagram className="mr-2 h-4 w-4" /> @core.sec
                  </a>
                </Button>
                <Button asChild variant="outline">
                  <Link to="/">Back to SentraX <ArrowRight className="ml-2 h-4 w-4" /></Link>
                </Button>
              </div>
            </div>
          </div>
        </Card>

        <div className="mt-12">
          <h3 className="text-center text-2xl font-semibold">What CoreSec brings to SentraX</h3>
          <div className="mt-8 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { icon: Search, t: "Penetration testing", d: "Manual exploitation and validation of high-risk findings raised by the platform." },
              { icon: Code2, t: "Secure development", d: "Code review and secure engineering support for client development teams." },
              { icon: Cpu, t: "AI defence research", d: "Detection models and threat intelligence feeding the SentraX scoring engine." },
              { icon: Cloud, t: "Cloud protection", d: "Hardening of cloud infrastructure, identity and deployment pipelines." },
            ].map((c) => (
              <Card key={c.t} className="border-border bg-card p-5">
                <c.icon className="h-5 w-5 text-primary" />
                <div className="mt-3 font-medium">{c.t}</div>
                <p className="mt-1 text-sm text-muted-foreground">{c.d}</p>
              </Card>
            ))}
          </div>
        </div>

        <div className="mt-12 grid gap-5 md:grid-cols-2">
          <Card className="border-border bg-card p-6">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <h4 className="mt-3 font-semibold">How the partnership works</h4>
            <p className="mt-2 text-sm text-muted-foreground">
              SentraX runs the continuous assessment and reporting layer. When a client needs hands-on
              work — a full penetration test, incident support or an architecture review — CoreSec's
              consultants take it on, using the SentraX report as the starting point.
            </p>
          </Card>
          <Card className="border-border bg-card p-6">
            <GraduationCap className="h-5 w-5 text-primary" />
            <h4 className="mt-3 font-semibold">Community & training</h4>
            <p className="mt-2 text-sm text-muted-foreground">
              CoreSec runs security awareness sessions and practical training for client teams and local
              students. Follow their work and upcoming sessions on Instagram at{" "}
              <a href="https://instagram.com/core.sec" target="_blank" rel="noreferrer" className="font-medium text-primary hover:underline">@core.sec</a>.
            </p>
          </Card>
        </div>

        <Card className="mt-12 border-border bg-secondary/50 p-8 text-center">
          <h3 className="text-xl font-semibold">Interested in partnering with SentraX?</h3>
          <p className="mx-auto mt-2 max-w-xl text-sm text-muted-foreground">
            We work with agencies, hosting providers and consultancies who want to offer security
            assessments to their own clients.
          </p>
          <Button asChild className="mt-6"><Link to="/">Get in touch</Link></Button>
        </Card>
      </section>
    </div>
  );
}
