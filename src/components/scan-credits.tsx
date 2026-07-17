import { Link } from "@tanstack/react-router";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Zap } from "lucide-react";
import { useCredits } from "@/hooks/use-credits";
import { PLAN_LABELS } from "@/lib/plan";

export function ScanCreditsCard() {
  const { data } = useCredits();
  if (!data) return null;
  const unlimited = data.limit === Infinity;
  const pct = unlimited ? 100 : Math.min(100, (data.used / data.limit) * 100);
  const remainingText = unlimited ? "Unlimited" : `${data.remaining} of ${data.limit}`;

  return (
    <Card className="border-border/60 bg-gradient-card p-6">
      <div className="flex items-center justify-between">
        <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Scan Credits</span>
        <span className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-[10px] font-mono uppercase text-primary">
          {PLAN_LABELS[data.plan]} plan
        </span>
      </div>
      <div className="mt-4 flex items-end gap-3">
        <div className="text-4xl font-bold text-gradient">{unlimited ? "∞" : data.remaining}</div>
        <div className="pb-2 text-sm text-muted-foreground">scans left</div>
      </div>
      <div className="mt-1 text-xs text-muted-foreground">{data.used} used · {remainingText}</div>
      <div className="mt-3 h-2 overflow-hidden rounded-full bg-muted">
        <div className="h-full bg-gradient-primary transition-all" style={{ width: `${pct}%` }} />
      </div>
      {!unlimited && data.remaining === 0 && (
        <Button asChild size="sm" className="mt-4 w-full bg-gradient-primary text-primary-foreground">
          <Link to="/upgrade"><Zap className="mr-2 h-4 w-4" />Upgrade plan</Link>
        </Button>
      )}
    </Card>
  );
}

export function ScanCreditsInline() {
  const { data } = useCredits();
  if (!data) return null;
  const unlimited = data.limit === Infinity;
  return (
    <div className="flex items-center gap-2 rounded-full border border-border/60 bg-background/60 px-3 py-1 text-xs">
      <Zap className="h-3.5 w-3.5 text-primary" />
      <span className="font-mono text-muted-foreground">
        {unlimited ? "Unlimited scans" : `${data.remaining}/${data.limit} scans left`}
      </span>
    </div>
  );
}
