import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/scan";

const cls: Record<Severity, string> = {
  critical: "bg-destructive/15 text-destructive border-destructive/30",
  high: "bg-danger/15 text-danger border-danger/30",
  medium: "bg-warning/15 text-warning border-warning/30",
  low: "bg-info/15 text-info border-info/30",
  info: "bg-muted text-muted-foreground border-border",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn("inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider", cls[severity], className)}>
      {severity}
    </span>
  );
}

export function RiskPill({ risk }: { risk: string }) {
  const tone = risk === "Low" ? "bg-success/15 text-success border-success/30"
    : risk === "High" ? "bg-destructive/15 text-destructive border-destructive/30"
    : "bg-warning/15 text-warning border-warning/30";
  return <span className={cn("inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium", tone)}>{risk} Risk</span>;
}
