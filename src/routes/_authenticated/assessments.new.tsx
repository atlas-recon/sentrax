import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { AppShell } from "@/components/app-shell";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Loader2, Check, ScanLine, Zap } from "lucide-react";
import { SCAN_STEPS } from "@/lib/scan";
import { runScan } from "@/lib/scan.functions";
import { cn } from "@/lib/utils";
import { useCredits } from "@/hooks/use-credits";
import { PLAN_LABELS } from "@/lib/plan";
import { useQueryClient } from "@tanstack/react-query";

export const Route = createFileRoute("/_authenticated/assessments/new")({
  head: () => ({ meta: [{ title: "New Assessment — SentraX" }] }),
  component: NewAssessment,
});

const schema = z.object({
  company_name: z.string().trim().min(2).max(120),
  website: z.string().trim().url("Enter a valid URL (https://...)"),
});

function NewAssessment() {
  const navigate = useNavigate();
  const scan = useServerFn(runScan);
  const qc = useQueryClient();
  const credits = useCredits();
  const [running, setRunning] = useState(false);
  const [step, setStep] = useState(-1);
  const [stepDetails, setStepDetails] = useState<Record<string, string>>({});

  const outOfCredits = credits.data && credits.data.limit !== Infinity && credits.data.remaining <= 0;

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (outOfCredits) { toast.error("You've used all your scans. Upgrade your plan to continue."); return; }
    const fd = new FormData(e.currentTarget);
    const parsed = schema.safeParse({ company_name: fd.get("company_name"), website: fd.get("website") });
    if (!parsed.success) { toast.error(parsed.error.issues[0].message); return; }

    setRunning(true);
    setStep(0);
    setStepDetails({});

    const { data: userData } = await supabase.auth.getUser();
    const user = userData.user!;

    const { data: company, error: cErr } = await supabase.from("companies").insert({
      user_id: user.id, company_name: parsed.data.company_name, website: parsed.data.website,
    }).select().single();
    if (cErr || !company) { toast.error(cErr?.message ?? "Failed"); setRunning(false); return; }

    // Animate step progression while the real scan runs in parallel
    let currentStep = 0;
    const interval = setInterval(() => {
      currentStep = Math.min(currentStep + 1, SCAN_STEPS.length - 1);
      setStep(currentStep);
    }, 900);

    let result;
    try {
      result = await scan({ data: { website: parsed.data.website } });
    } catch (err) {
      clearInterval(interval);
      toast.error(err instanceof Error ? err.message : "Scan failed");
      setRunning(false);
      return;
    }
    clearInterval(interval);

    const details: Record<string, string> = {};
    for (const s of result.steps) details[s.key] = s.detail;
    setStepDetails(details);

    const { data: assessment, error: aErr } = await supabase.from("assessments").insert({
      user_id: user.id, company_id: company.id, security_score: result.score, risk_level: result.risk, status: "completed",
    }).select().single();
    if (aErr || !assessment) { toast.error(aErr?.message ?? "Failed"); setRunning(false); return; }

    if (result.findings.length) {
      await supabase.from("findings").insert(result.findings.map((f) => ({
        assessment_id: assessment.id,
        user_id: user.id,
        title: f.title,
        severity: f.severity,
        description: f.description,
        recommendation: f.recommendation,
      })));
    }

    await supabase.from("reports").insert({
      assessment_id: assessment.id, user_id: user.id,
      content: JSON.parse(JSON.stringify({
        summary: `Live scan of ${parsed.data.website} completed. Score ${result.score}/100 (${result.risk} risk). ${result.findings.length} findings across headers, TLS, cookies, and tech fingerprint.`,
        score: result.score, risk: result.risk,
        findings: result.findings,
        website: parsed.data.website,
        target: result.target,
        tech: result.tech,
        steps: result.steps,
      })),
    });

    setStep(SCAN_STEPS.length);
    qc.invalidateQueries({ queryKey: ["credits"] });
    toast.success(`Scan complete — ${result.findings.length} findings`);
    setTimeout(() => navigate({ to: "/reports/$id", params: { id: assessment.id } }), 500);
  }

  return (
    <AppShell title="New Security Assessment">
      {credits.data && (
        <Card className="mb-4 flex flex-wrap items-center justify-between gap-3 border-border/60 bg-gradient-card p-4">
          <div className="flex items-center gap-3">
            <div className="grid h-9 w-9 place-items-center rounded-md bg-primary/15 text-primary"><Zap className="h-4 w-4" /></div>
            <div>
              <div className="text-sm font-medium">
                {credits.data.limit === Infinity
                  ? "Unlimited scans"
                  : `${credits.data.remaining} of ${credits.data.limit} scans remaining`}
              </div>
              <div className="text-xs text-muted-foreground">{PLAN_LABELS[credits.data.plan]} plan · {credits.data.used} used</div>
            </div>
          </div>
          {outOfCredits && (
            <Button asChild size="sm" className="bg-gradient-primary text-primary-foreground">
              <Link to="/" hash="pricing">Upgrade plan</Link>
            </Button>
          )}
        </Card>
      )}
      <div className="grid gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-2 border-border/60 bg-gradient-card p-6">
          <h2 className="font-semibold">Target</h2>
          <p className="mt-1 text-sm text-muted-foreground">Provide the company and website you want to assess. Findings are generated by SentraX's baseline analyzer.</p>
          <form onSubmit={onSubmit} className="mt-6 space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="company_name">Company Name</Label>
              <Input id="company_name" name="company_name" placeholder="Acme, Inc." disabled={running || !!outOfCredits} required />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="website">Website URL</Label>
              <Input id="website" name="website" type="url" placeholder="https://acme.com" disabled={running || !!outOfCredits} required />
            </div>
            <Button type="submit" className="w-full bg-gradient-primary text-primary-foreground shadow-glow" disabled={running || !!outOfCredits}>
              {running ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Scanning…</> : outOfCredits ? "No scans left" : <><ScanLine className="mr-2 h-4 w-4" />Run Assessment</>}
            </Button>
          </form>
        </Card>

        <Card className="lg:col-span-3 border-border/60 bg-gradient-card p-6">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="font-semibold">Scan Workflow</h2>
            <span className="font-mono text-xs text-muted-foreground">SentraX Analyzer v1.0</span>
          </div>
          <div className="relative overflow-hidden rounded-lg border border-border/60 bg-background/40 p-6">
            {running && <div className="pointer-events-none absolute inset-x-0 top-0 h-16 bg-primary/10 blur-2xl animate-scan" />}
            <ol className="space-y-4">
              {SCAN_STEPS.map((s, i) => {
                const state = step > i ? "done" : step === i ? "active" : "pending";
                return (
                  <li key={s.key} className="flex items-start gap-3">
                    <div className={cn(
                      "mt-0.5 grid h-7 w-7 place-items-center rounded-full border font-mono text-xs",
                      state === "done" && "border-success bg-success/15 text-success",
                      state === "active" && "border-primary bg-primary/15 text-primary animate-pulse-glow",
                      state === "pending" && "border-border text-muted-foreground",
                    )}>
                      {state === "done" ? <Check className="h-4 w-4" /> : i + 1}
                    </div>
                    <div className="flex-1">
                      <div className={cn("font-medium", state === "pending" && "text-muted-foreground")}>{s.label}</div>
                      <div className="font-mono text-xs text-muted-foreground">{stepDetails[s.key] ?? s.detail}</div>
                    </div>
                  </li>
                );
              })}
            </ol>
          </div>
          <p className="mt-4 text-xs text-muted-foreground">Live scan performs real HTTP fetch, TLS reachability, header inspection, cookie analysis, and technology fingerprinting. Ready to plug into OWASP ZAP & Nmap.</p>
        </Card>
      </div>
    </AppShell>
  );
}

