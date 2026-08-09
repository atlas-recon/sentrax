import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { AppShell } from "@/components/app-shell";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Check, Copy, Phone, Smartphone, Clock, ShieldCheck, ArrowLeft } from "lucide-react";

export const Route = createFileRoute("/_authenticated/upgrade")({
  head: () => ({ meta: [{ title: "Upgrade — SentraX" }] }),
  component: UpgradePage,
});

const MERCHANT_PHONE = "+255 773 841 274";
const MERCHANT_PHONE_DIAL = "+255773841274";
const PROVIDER = "Mixx by Yas";

const PLANS = [
  { id: "pro" as const, name: "Pro", price: 10, features: ["5 websites", "Unlimited re-scans", "AI recommendations", "PDF reports"] },
  { id: "business" as const, name: "Business", price: 50, features: ["Unlimited websites", "Continuous scanning", "Team dashboards", "Priority support"] },
];

function makeRef() {
  return "SX-" + Math.random().toString(36).slice(2, 6).toUpperCase() + "-" + Date.now().toString(36).slice(-4).toUpperCase();
}

const schema = z.object({
  payer_name: z.string().trim().min(2, "Enter your name").max(120),
  payer_phone: z.string().trim().min(9, "Enter the phone you paid from").max(20),
  transaction_id: z.string().trim().min(4, "Enter the M-Pesa/Mixx transaction ID").max(60),
});

function UpgradePage() {
  const qc = useQueryClient();
  const [plan, setPlan] = useState<"pro" | "business">("pro");
  const [reference] = useState(makeRef);
  const [submitting, setSubmitting] = useState(false);

  const active = PLANS.find((p) => p.id === plan)!;

  const requests = useQuery({
    queryKey: ["payment_requests"],
    queryFn: async () => {
      const { data } = await supabase.from("payment_requests").select("*").order("created_at", { ascending: false }).limit(10);
      return data ?? [];
    },
  });

  const copy = async (text: string, label: string) => {
    try { await navigator.clipboard.writeText(text); toast.success(`${label} copied`); }
    catch { toast.error("Copy failed"); }
  };

  const ussdString = useMemo(() => `Pay ${active.price} USD to ${MERCHANT_PHONE} via ${PROVIDER}`, [active]);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const parsed = schema.safeParse({
      payer_name: fd.get("payer_name"),
      payer_phone: fd.get("payer_phone"),
      transaction_id: fd.get("transaction_id"),
    });
    if (!parsed.success) { toast.error(parsed.error.issues[0].message); return; }
    setSubmitting(true);
    const { data: userData } = await supabase.auth.getUser();
    const user = userData.user;
    if (!user) { toast.error("Not signed in"); setSubmitting(false); return; }
    const { error } = await supabase.from("payment_requests").insert({
      user_id: user.id,
      plan,
      amount_usd: active.price,
      reference_code: reference,
      payer_name: parsed.data.payer_name,
      payer_phone: parsed.data.payer_phone,
      transaction_id: parsed.data.transaction_id,
    });
    setSubmitting(false);
    if (error) { toast.error(error.message); return; }
    toast.success("Payment submitted for review. We'll upgrade your plan shortly.");
    qc.invalidateQueries({ queryKey: ["payment_requests"] });
    (e.target as HTMLFormElement).reset();
  }

  if (desktop) {
    return (
      <AppShell
        title="Plan"
        actions={<Button asChild variant="outline" size="sm"><Link to="/dashboard"><ArrowLeft className="mr-2 h-4 w-4" />Dashboard</Link></Button>}
      >
        <Card className="max-w-2xl border-border/60 bg-gradient-card p-8 text-center">
          <div className="mx-auto grid h-12 w-12 place-items-center rounded-lg bg-primary/15 text-primary"><ShieldCheck className="h-6 w-6" /></div>
          <h2 className="mt-4 text-xl font-semibold">Everything is unlocked</h2>
          <p className="mt-2 text-sm text-muted-foreground">
            You are running the SentraX Linux desktop build. Unlimited website assessments, all OWASP checks and
            full PDF reporting are enabled — there is no payment or subscription on Linux.
          </p>
          <Button asChild className="mt-6 bg-gradient-primary text-primary-foreground shadow-glow">
            <Link to="/assessments/new">Run an assessment</Link>
          </Button>
        </Card>
      </AppShell>
    );
  }

  return (

    <AppShell
      title="Upgrade Plan"
      actions={<Button asChild variant="outline" size="sm"><Link to="/dashboard"><ArrowLeft className="mr-2 h-4 w-4" />Dashboard</Link></Button>}
    >
      <div className="grid gap-6 lg:grid-cols-5">
        {/* Plan picker */}
        <Card className="lg:col-span-2 border-border/60 bg-gradient-card p-6">
          <h2 className="font-semibold">1. Choose a plan</h2>
          <p className="mt-1 text-sm text-muted-foreground">Pay via mobile money. Your plan activates once we confirm the transaction (usually within 1 hour).</p>
          <div className="mt-5 space-y-3">
            {PLANS.map((p) => (
              <button
                key={p.id}
                onClick={() => setPlan(p.id)}
                className={`w-full rounded-lg border p-4 text-left transition-colors ${plan === p.id ? "border-primary bg-primary/10" : "border-border/60 hover:bg-accent/40"}`}
              >
                <div className="flex items-center justify-between">
                  <div className="font-semibold">{p.name}</div>
                  <div className="text-2xl font-bold text-gradient">${p.price}<span className="text-xs font-normal text-muted-foreground">/mo</span></div>
                </div>
                <ul className="mt-2 space-y-1">
                  {p.features.map((f) => (
                    <li key={f} className="flex items-center gap-2 text-xs text-muted-foreground"><Check className="h-3 w-3 text-primary" />{f}</li>
                  ))}
                </ul>
              </button>
            ))}
          </div>
        </Card>

        {/* Payment instructions */}
        <Card className="lg:col-span-3 border-border/60 bg-gradient-card p-6">
          <h2 className="font-semibold">2. Pay via {PROVIDER}</h2>
          <p className="mt-1 text-sm text-muted-foreground">Send exactly <span className="font-mono text-foreground">${active.price} USD</span> (or the TZS equivalent) using the details below.</p>

          <div className="mt-5 space-y-3">
            <PayField label="Provider" value={PROVIDER} icon={Smartphone} />
            <PayField label="Merchant phone" value={MERCHANT_PHONE} icon={Phone} onCopy={() => copy(MERCHANT_PHONE_DIAL, "Phone number")} />
            <PayField label="Amount" value={`$${active.price} USD`} onCopy={() => copy(String(active.price), "Amount")} />
            <PayField label="Reference code (put in narrative)" value={reference} onCopy={() => copy(reference, "Reference")} highlight />
          </div>

          <div className="mt-6 rounded-lg border border-primary/30 bg-primary/5 p-4 text-sm">
            <div className="flex items-start gap-2">
              <ShieldCheck className="mt-0.5 h-4 w-4 text-primary" />
              <div>
                <div className="font-medium text-foreground">How to pay</div>
                <ol className="mt-2 list-decimal space-y-1 pl-4 text-muted-foreground">
                  <li>Open the Mixx by Yas app or dial the Yas USSD menu.</li>
                  <li>Choose <span className="text-foreground">Send Money</span> to <span className="font-mono text-foreground">{MERCHANT_PHONE}</span>.</li>
                  <li>Enter the amount <span className="font-mono text-foreground">${active.price} USD</span> equivalent in TZS.</li>
                  <li>Put the reference code <span className="font-mono text-foreground">{reference}</span> in the reason/narrative field.</li>
                  <li>Complete the payment and copy the transaction ID from the SMS.</li>
                </ol>
              </div>
            </div>
          </div>

          {/* Confirmation form */}
          <form onSubmit={onSubmit} className="mt-6 space-y-4 border-t border-border/60 pt-6">
            <h3 className="font-semibold">3. Submit your payment</h3>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="payer_name">Your name</Label>
                <Input id="payer_name" name="payer_name" placeholder="Full name" required />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="payer_phone">Phone you paid from</Label>
                <Input id="payer_phone" name="payer_phone" placeholder="+255 ..." required />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="transaction_id">Transaction ID (from Mixx/Yas SMS)</Label>
              <Input id="transaction_id" name="transaction_id" placeholder="e.g. CFH9K23L07" required />
            </div>
            <Button type="submit" disabled={submitting} className="w-full bg-gradient-primary text-primary-foreground shadow-glow">
              {submitting ? "Submitting…" : `Submit ${active.name} payment for review`}
            </Button>
            <p className="text-xs text-muted-foreground">By submitting you confirm you sent ${active.price} USD via {PROVIDER} to {MERCHANT_PHONE} with reference {reference}. Reviews take up to 1 hour.</p>
          </form>
        </Card>
      </div>

      {/* History */}
      {requests.data && requests.data.length > 0 && (
        <Card className="mt-6 border-border/60 bg-gradient-card p-6">
          <h2 className="mb-4 font-semibold">Your payment requests</h2>
          <div className="space-y-2">
            {requests.data.map((r) => (
              <div key={r.id} className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border/60 bg-background/40 p-3 text-sm">
                <div className="flex items-center gap-3">
                  <Clock className="h-4 w-4 text-muted-foreground" />
                  <div>
                    <div className="font-medium capitalize">{r.plan} plan · ${Number(r.amount_usd)}</div>
                    <div className="font-mono text-xs text-muted-foreground">{r.reference_code} · {new Date(r.created_at).toLocaleString()}</div>
                  </div>
                </div>
                <StatusPill status={r.status} />
              </div>
            ))}
          </div>
        </Card>
      )}
    </AppShell>
  );
}

function PayField({ label, value, icon: Icon, onCopy, highlight }: { label: string; value: string; icon?: React.ComponentType<{ className?: string }>; onCopy?: () => void; highlight?: boolean }) {
  return (
    <div className={`flex items-center justify-between gap-3 rounded-md border p-3 ${highlight ? "border-primary/40 bg-primary/10" : "border-border/60 bg-background/40"}`}>
      <div className="min-w-0 flex-1">
        <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</div>
        <div className="flex items-center gap-2 truncate font-mono text-sm text-foreground">
          {Icon && <Icon className="h-4 w-4 text-primary" />}
          {value}
        </div>
      </div>
      {onCopy && (
        <Button type="button" variant="ghost" size="sm" onClick={onCopy}><Copy className="h-4 w-4" /></Button>
      )}
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    pending: "bg-warning/15 text-warning border-warning/30",
    confirmed: "bg-success/15 text-success border-success/30",
    rejected: "bg-destructive/15 text-destructive border-destructive/30",
  };
  return <span className={`rounded-full border px-2 py-0.5 text-[10px] font-mono uppercase ${map[status] ?? "border-border/60 text-muted-foreground"}`}>{status}</span>;
}
