import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { AppShell } from "@/components/app-shell";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { useQuery } from "@tanstack/react-query";

export const Route = createFileRoute("/_authenticated/profile")({
  head: () => ({ meta: [{ title: "Profile — Shahin Security" }] }),
  component: Profile,
});

function Profile() {
  const [saving, setSaving] = useState(false);
  const [fullName, setFullName] = useState("");
  const [prefs, setPrefs] = useState({ weekly: true, alerts: true });

  const q = useQuery({
    queryKey: ["profile"],
    queryFn: async () => {
      const { data: userData } = await supabase.auth.getUser();
      const { data: profile } = await supabase.from("profiles").select("*").eq("id", userData.user!.id).maybeSingle();
      const { data: companies } = await supabase.from("companies").select("*").order("created_at", { ascending: false });
      return { user: userData.user, profile, companies: companies ?? [] };
    },
  });

  useEffect(() => { if (q.data?.profile?.full_name) setFullName(q.data.profile.full_name); }, [q.data?.profile?.full_name]);

  async function save() {
    if (!q.data?.user) return;
    setSaving(true);
    const { error } = await supabase.from("profiles").upsert({ id: q.data.user.id, full_name: fullName });
    setSaving(false);
    if (error) toast.error(error.message); else toast.success("Profile updated");
  }

  return (
    <AppShell title="Profile & Settings">
      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="border-border/60 bg-gradient-card p-6">
          <h2 className="font-semibold">Account information</h2>
          <div className="mt-4 space-y-4">
            <div className="space-y-1.5">
              <Label>Email</Label>
              <Input value={q.data?.user?.email ?? ""} disabled />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="fn">Full name</Label>
              <Input id="fn" value={fullName} onChange={(e) => setFullName(e.target.value)} />
            </div>
            <Button onClick={save} disabled={saving} className="bg-gradient-primary text-primary-foreground">Save changes</Button>
          </div>
        </Card>

        <Card className="border-border/60 bg-gradient-card p-6">
          <h2 className="font-semibold">Security preferences</h2>
          <div className="mt-4 space-y-4">
            <PrefRow label="Weekly security digest" desc="Get a summary of your posture every Monday." checked={prefs.weekly} onChange={(v) => setPrefs((p) => ({ ...p, weekly: v }))} />
            <PrefRow label="Critical alert emails" desc="Immediate alert when a critical finding is detected." checked={prefs.alerts} onChange={(v) => setPrefs((p) => ({ ...p, alerts: v }))} />
          </div>
        </Card>

        <Card className="border-border/60 bg-gradient-card p-6 lg:col-span-2">
          <h2 className="font-semibold">Companies</h2>
          <p className="text-sm text-muted-foreground">Companies you've assessed with Shahin Security.</p>
          <div className="mt-4 divide-y divide-border/60 rounded-md border border-border/60">
            {(q.data?.companies ?? []).map((c) => (
              <div key={c.id} className="flex items-center justify-between p-4">
                <div>
                  <div className="font-medium">{c.company_name}</div>
                  <div className="font-mono text-xs text-muted-foreground">{c.website}</div>
                </div>
                <div className="text-xs text-muted-foreground">{new Date(c.created_at).toLocaleDateString()}</div>
              </div>
            ))}
            {(q.data?.companies ?? []).length === 0 && <div className="p-6 text-center text-sm text-muted-foreground">No companies yet.</div>}
          </div>
        </Card>
      </div>
    </AppShell>
  );
}

function PrefRow({ label, desc, checked, onChange }: { label: string; desc: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-md border border-border/60 p-4">
      <div className="min-w-0">
        <div className="font-medium">{label}</div>
        <div className="text-xs text-muted-foreground">{desc}</div>
      </div>
      <Switch checked={checked} onCheckedChange={onChange} />
    </div>
  );
}
