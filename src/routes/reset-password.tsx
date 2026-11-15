import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { z } from "zod";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card } from "@/components/ui/card";
import { Logo } from "@/components/logo";
import { Loader2 } from "lucide-react";

export const Route = createFileRoute("/reset-password")({
  head: () => ({ meta: [{ title: "Reset password — Shahin Security" }] }),
  component: ResetPassword,
});

function ResetPassword() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const pw = new FormData(e.currentTarget).get("password");
    const parsed = z.string().min(8).safeParse(pw);
    if (!parsed.success) { toast.error("Password must be at least 8 characters"); return; }
    setLoading(true);
    const { error } = await supabase.auth.updateUser({ password: parsed.data });
    setLoading(false);
    if (error) { toast.error(error.message); return; }
    toast.success("Password updated");
    navigate({ to: "/dashboard" });
  }
  return (
    <div className="relative flex min-h-screen items-center justify-center bg-hero px-4">
      <div className="absolute inset-0 grid-bg opacity-30" />
      <div className="relative w-full max-w-md">
        <div className="mb-6 flex justify-center"><Logo /></div>
        <Card className="border-border/60 bg-gradient-card p-6">
          <h1 className="text-xl font-semibold">Choose a new password</h1>
          <form onSubmit={onSubmit} className="mt-4 space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="password">New password</Label>
              <Input id="password" name="password" type="password" required />
            </div>
            <Button type="submit" className="w-full bg-gradient-primary text-primary-foreground" disabled={loading}>
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}Update password
            </Button>
          </form>
        </Card>
      </div>
    </div>
  );
}
