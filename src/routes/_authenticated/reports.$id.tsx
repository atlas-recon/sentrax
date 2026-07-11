import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { AppShell } from "@/components/app-shell";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { RiskPill, SeverityBadge } from "@/components/severity-badge";
import { Download, ArrowLeft, Loader2 } from "lucide-react";
import { toast } from "sonner";
import type { Severity } from "@/lib/scan";
import { generateReportPdf, type PdfFinding } from "@/lib/pdf-report";

type ReportContent = {
  summary?: string;
  score?: number;
  risk?: string;
  website?: string;
  findings?: Array<{
    title: string;
    severity: Severity;
    description: string;
    recommendation: string;
    category?: string;
    evidence?: string;
  }>;
  tech?: Array<{ name: string; source: string; evidence: string }> | string[];
  target?: {
    url: string;
    finalUrl: string;
    statusCode: number;
    protocol: string;
    hstsRedirect: boolean;
    server?: string;
    poweredBy?: string;
    responseHeaders?: Record<string, string>;
    setCookies?: Array<{
      name: string; raw: string; secure: boolean; httpOnly: boolean; sameSite?: string;
    }>;
    redirectChain?: Array<{ url: string; status: number; location?: string }>;
    httpToHttpsChain?: Array<{ url: string; status: number; location?: string }>;
  };
};

const SECURITY_HEADER_KEYS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "cross-origin-embedder-policy",
  "server",
  "x-powered-by",
];

export const Route = createFileRoute("/_authenticated/reports/$id")({
  head: () => ({ meta: [{ title: "Report — SentraX" }] }),
  component: ReportDetail,
});

function ReportDetail() {
  const { id } = Route.useParams();
  const q = useQuery({
    queryKey: ["report", id],
    queryFn: async () => {
      const [assessment, findings, report] = await Promise.all([
        supabase.from("assessments")
          .select("id, security_score, risk_level, created_at, companies(company_name, website)")
          .eq("id", id).single(),
        supabase.from("findings").select("*").eq("assessment_id", id).order("severity"),
        supabase.from("reports").select("content").eq("assessment_id", id).maybeSingle(),
      ]);
      return {
        a: assessment.data,
        findings: findings.data ?? [],
        content: (report.data?.content ?? null) as ReportContent | null,
      };
    },
  });

  const a = q.data?.a;
  const dbFindings = q.data?.findings ?? [];
  const content = q.data?.content;
  // Prefer rich findings (with evidence) from the report content JSONB;
  // fall back to the flat findings table if the report predates evidence.
  const findings =
    content?.findings && content.findings.length
      ? content.findings.map((f, i) => ({ id: `c-${i}`, ...f }))
      : dbFindings.map((f) => ({ ...f, evidence: undefined as string | undefined, category: undefined as string | undefined }));

  const target = content?.target;
  const tech = content?.tech;

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
          {/* Executive summary */}
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

          {/* Scan details */}
          {target && (
            <Card className="border-border/60 bg-gradient-card p-6">
              <h3 className="mb-4 font-semibold">Scan Details</h3>
              <div className="grid gap-6 md:grid-cols-2">
                <div>
                  <SectionLabel>Target</SectionLabel>
                  <KV k="Requested" v={target.url} mono />
                  <KV k="Final URL" v={target.finalUrl} mono />
                  <KV k="HTTP status" v={String(target.statusCode)} mono />
                  <KV k="Protocol" v={target.protocol} mono />
                  <KV k="HTTP→HTTPS" v={target.hstsRedirect ? "redirects" : "no redirect"} mono />
                  {target.server && <KV k="Server" v={target.server} mono />}
                  {target.poweredBy && <KV k="X-Powered-By" v={target.poweredBy} mono />}
                </div>
                <div>
                  <SectionLabel>Redirect chain</SectionLabel>
                  <EvidenceBlock text={formatChain(target.redirectChain)} />
                  {target.httpToHttpsChain && target.httpToHttpsChain.length > 0 && (
                    <>
                      <SectionLabel className="mt-4">HTTP probe chain</SectionLabel>
                      <EvidenceBlock text={formatChain(target.httpToHttpsChain)} />
                    </>
                  )}
                </div>
              </div>

              <div className="mt-6 grid gap-6 md:grid-cols-2">
                <div>
                  <SectionLabel>Security-relevant response headers</SectionLabel>
                  <EvidenceBlock text={formatHeaders(target.responseHeaders)} />
                </div>
                <div>
                  <SectionLabel>Set-Cookie ({target.setCookies?.length ?? 0})</SectionLabel>
                  {target.setCookies && target.setCookies.length > 0 ? (
                    <div className="space-y-2">
                      {target.setCookies.map((c, i) => (
                        <div key={i} className="rounded-md border border-border/60 bg-background/60 p-3">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="font-mono text-xs font-semibold">{c.name}</span>
                            <AttrChip ok={c.secure} label="Secure" />
                            <AttrChip ok={c.httpOnly} label="HttpOnly" />
                            <AttrChip ok={!!c.sameSite} label={c.sameSite ? `SameSite=${c.sameSite}` : "SameSite"} />
                          </div>
                          <pre className="mt-2 whitespace-pre-wrap break-all font-mono text-[11px] leading-relaxed text-muted-foreground">{c.raw}</pre>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EvidenceBlock text="(no Set-Cookie on final response)" />
                  )}
                </div>
              </div>

              {tech && Array.isArray(tech) && tech.length > 0 && (
                <div className="mt-6">
                  <SectionLabel>Technology detection</SectionLabel>
                  <div className="space-y-1.5">
                    {(tech as Array<{ name: string; source: string; evidence: string } | string>).map((t, i) => (
                      <div key={i} className="rounded-md border border-border/60 bg-background/60 px-3 py-2 font-mono text-xs">
                        {typeof t === "string" ? t : (
                          <>
                            <span className="font-semibold">{t.name}</span>{" "}
                            <span className="text-muted-foreground">— via {t.source}: {t.evidence}</span>
                          </>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </Card>
          )}

          {/* Findings */}
          <Card className="border-border/60 bg-gradient-card p-6">
            <h3 className="mb-4 font-semibold">Findings</h3>
            <div className="space-y-4">
              {findings.map((f) => (
                <div key={f.id} className="rounded-lg border border-border/60 bg-background/40 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="font-medium">{f.title}</div>
                    <div className="flex items-center gap-2">
                      {f.category && (
                        <span className="rounded-full border border-border/60 px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                          {f.category}
                        </span>
                      )}
                      <SeverityBadge severity={f.severity as Severity} />
                    </div>
                  </div>
                  <div className="mt-3 grid gap-3 md:grid-cols-2">
                    <div>
                      <SectionLabel>Impact</SectionLabel>
                      <p className="text-sm text-muted-foreground">{f.description}</p>
                    </div>
                    <div>
                      <SectionLabel>Recommendation</SectionLabel>
                      <p className="text-sm">{f.recommendation}</p>
                    </div>
                  </div>
                  {f.evidence && (
                    <div className="mt-3">
                      <SectionLabel>Evidence</SectionLabel>
                      <EvidenceBlock text={f.evidence} />
                    </div>
                  )}
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

function SectionLabel({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`mb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground ${className}`}>
      {children}
    </div>
  );
}

function KV({ k, v, mono = false }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex gap-3 py-1 text-sm border-b border-border/40 last:border-0">
      <div className="w-32 shrink-0 text-muted-foreground">{k}</div>
      <div className={`flex-1 break-all ${mono ? "font-mono text-xs" : ""}`}>{v}</div>
    </div>
  );
}

function EvidenceBlock({ text }: { text: string }) {
  return (
    <pre className="max-h-64 overflow-auto rounded-md border border-border/60 bg-background/70 p-3 font-mono text-[11px] leading-relaxed text-muted-foreground whitespace-pre-wrap break-all">
      {text}
    </pre>
  );
}

function AttrChip({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] ${ok ? "bg-success/15 text-success" : "bg-destructive/15 text-destructive"}`}>
      {ok ? "✓" : "✗"} {label}
    </span>
  );
}

function formatChain(chain?: Array<{ url: string; status: number; location?: string }>) {
  if (!chain || chain.length === 0) return "(no redirects — direct response)";
  return chain
    .map((h, i) => `[${i}] ${h.status || "ERR"} ${h.url}${h.location ? `\n     → Location: ${h.location}` : ""}`)
    .join("\n");
}

function formatHeaders(headers?: Record<string, string>) {
  if (!headers) return "(no headers recorded)";
  const lines: string[] = [];
  for (const key of SECURITY_HEADER_KEYS) {
    if (headers[key]) lines.push(`${key}: ${headers[key]}`);
    else lines.push(`${key}: — not set`);
  }
  return lines.join("\n");
}
