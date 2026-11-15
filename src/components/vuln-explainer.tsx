import { useState } from "react";
import { Card } from "@/components/ui/card";
import { ChevronDown, BookOpen, ShieldAlert, Bug, Wrench, Target } from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import { VULN_DOCS, matchDocs, type VulnDoc } from "@/lib/vuln-glossary";
import { cn } from "@/lib/utils";

export function VulnExplainer({ findingTitles }: { findingTitles: string[] }) {
  const matched = matchDocs(findingTitles);
  const docs = matched.length > 0 ? matched : VULN_DOCS.slice(0, 6).map((doc) => ({ doc, count: 0 }));

  return (
    <Card className="border-border/60 bg-gradient-card p-6">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <BookOpen className="h-4 w-4 text-primary" />
          <h2 className="font-semibold">Vulnerability Explainer</h2>
        </div>
        <span className="font-mono text-xs text-muted-foreground">
          {matched.length > 0 ? `${matched.length} categories detected` : "Common threats"}
        </span>
      </div>
      <p className="mb-4 text-xs text-muted-foreground">
        Plain-English breakdown of every issue class Shahin Security checks — what it is, how attackers exploit it, and how to fix it.
      </p>
      <div className="space-y-2">
        {docs.map(({ doc, count }) => (
          <VulnRow key={doc.slug} doc={doc} count={count} />
        ))}
      </div>
    </Card>
  );
}

function VulnRow({ doc, count }: { doc: VulnDoc; count: number }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-border/60 bg-background/40">
      <button onClick={() => setOpen((v) => !v)} className="flex w-full items-center justify-between gap-3 p-3 text-left transition-colors hover:bg-accent/40">
        <div className="flex min-w-0 items-center gap-3">
          <SeverityBadge severity={doc.severity} />
          <div className="min-w-0">
            <div className="truncate font-medium">{doc.title}</div>
            <div className="truncate font-mono text-[10px] text-muted-foreground">{doc.owasp}</div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {count > 0 && (
            <span className="rounded-full border border-destructive/40 bg-destructive/10 px-2 py-0.5 text-[10px] font-mono uppercase text-destructive">
              {count} found
            </span>
          )}
          <ChevronDown className={cn("h-4 w-4 text-muted-foreground transition-transform", open && "rotate-180")} />
        </div>
      </button>
      {open && (
        <div className="grid gap-3 border-t border-border/60 p-4 sm:grid-cols-2">
          <Section icon={ShieldAlert} label="What it is" text={doc.what} />
          <Section icon={Bug} label="How it's exploited" text={doc.how} />
          <Section icon={Target} label="Real-world impact" text={doc.impact} />
          <Section icon={Wrench} label="How to fix" text={doc.fix} />
        </div>
      )}
    </div>
  );
}

function Section({ icon: Icon, label, text }: { icon: React.ComponentType<{ className?: string }>; label: string; text: string }) {
  return (
    <div>
      <div className="mb-1 flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        <Icon className="h-3 w-3 text-primary" />{label}
      </div>
      <p className="text-sm leading-relaxed text-foreground/90">{text}</p>
    </div>
  );
}
