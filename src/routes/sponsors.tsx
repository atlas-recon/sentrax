import { createFileRoute, Link } from "@tanstack/react-router";
import coreSecLogo from "@/assets/coresec-logo.png";
import sentraxAsset from "@/assets/sentrax-logo.png.asset.json";
import { SiteHeader } from "@/components/site-header";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowRight, ShieldCheck, Cpu, Cloud, Code2 } from "lucide-react";

export const Route = createFileRoute("/sponsors")({
  head: () => ({
    meta: [
      { title: "Sponsors — SentraX" },
      { name: "description", content: "Partners and sponsors backing SentraX." },
    ],
  }),
  component: SponsorsPage,
});

function SponsorsPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <SiteHeader />
      <section className="relative overflow-hidden bg-hero">
        <div className="absolute inset-0 grid-bg opacity-30" />
        <div className="relative mx-auto max-w-5xl px-4 py-20 text-center sm:px-6">
          <div className="mx-auto mb-6 inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-xs font-medium text-primary">
            <ShieldCheck className="h-3.5 w-3.5" /> Trusted partners
          </div>
          <h1 className="text-balance text-4xl font-bold tracking-tight sm:text-5xl">
            Backed by <span className="text-gradient">CoreSec</span>
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-muted-foreground">
            SentraX is proudly sponsored by CoreSec — a cybersecurity engineering studio building the tools that keep modern businesses safe.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-4 py-16 sm:px-6">
        <Card className="overflow-hidden border-border/60 bg-gradient-card p-8 shadow-elegant">
          <div className="grid items-center gap-8 md:grid-cols-2">
            <div className="relative">
              <div className="absolute -inset-6 rounded-2xl bg-primary/20 blur-3xl" />
              <img
                src={coreSecLogo}
                alt="CoreSec — Secure Today, Protect Tomorrow"
                className="relative mx-auto w-full max-w-md rounded-xl"
              />
            </div>
            <div>
              <p className="font-mono text-xs uppercase tracking-widest text-primary">Platinum Sponsor</p>
              <h2 className="mt-2 text-3xl font-bold">CoreSec</h2>
              <p className="mt-1 text-sm italic text-muted-foreground">Secure Today, Protect Tomorrow.</p>
              <p className="mt-4 text-muted-foreground">
                CoreSec delivers end-to-end cybersecurity, secure development, AI-driven defense, and cloud protection for growing companies. Their engineering team powers the research behind SentraX's scanning engine.
              </p>
              <div className="mt-6 grid grid-cols-2 gap-3">
                <Pill icon={ShieldCheck} label="Cybersecurity" />
                <Pill icon={Code2} label="Development" />
                <Pill icon={Cpu} label="AI Solutions" />
                <Pill icon={Cloud} label="Cloud Security" />
              </div>
              <Button asChild className="mt-6 bg-gradient-primary text-primary-foreground shadow-glow">
                <Link to="/">Back to SentraX <ArrowRight className="ml-2 h-4 w-4" /></Link>
              </Button>
            </div>
          </div>
        </Card>

        <div className="mt-10 flex items-center justify-center gap-6 opacity-80">
          <img src={sentraxAsset.url} alt="SentraX" className="h-10 w-auto" />
          <span className="font-mono text-xs text-muted-foreground">× powered together ×</span>
          <img src={coreSecLogo} alt="CoreSec" className="h-10 w-auto" />
        </div>
      </section>
    </div>
  );
}

function Pill({ icon: Icon, label }: { icon: React.ComponentType<{ className?: string }>; label: string }) {
  return (
    <div className="flex items-center gap-2 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm">
      <Icon className="h-4 w-4 text-primary" /> {label}
    </div>
  );
}
