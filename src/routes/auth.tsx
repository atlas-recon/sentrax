import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { z } from "zod";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { lovable } from "@/integrations/lovable/index";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Logo } from "@/components/logo";
import { Loader2 } from "lucide-react";

const searchSchema = z.object({ mode: z.enum(["login", "register", "forgot"]).optional() });

export const Route = createFileRoute("/auth")({
  validateSearch: (s) => searchSchema.parse(s),
  head: () => ({
    meta: [
      { title: "Sign in — Shahin Security" },
      { name: "description", content: "Sign in or create your Shahin Security account." },
    ],
  }),
  component: AuthPage,
});

function AuthPage() {
  const { mode } = Route.useSearch();
  const navigate = useNavigate();

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) navigate({ to: "/dashboard", replace: true });
    });
  }, [navigate]);

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-hero px-4 py-10">
      <div className="absolute inset-0 grid-bg opacity-30" />
      <div className="relative w-full max-w-md">
        <Link to="/" className="mb-6 flex justify-center"><Logo /></Link>
        <Card className="border-border/60 bg-gradient-card p-6 shadow-elegant">
          <Tabs defaultValue={mode ?? "login"}>
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="login">Sign in</TabsTrigger>
              <TabsTrigger value="register">Register</TabsTrigger>
              <TabsTrigger value="forgot">Reset</TabsTrigger>
            </TabsList>
            <TabsContent value="login" className="pt-4"><LoginForm /></TabsContent>
            <TabsContent value="register" className="pt-4"><RegisterForm /></TabsContent>
            <TabsContent value="forgot" className="pt-4"><ForgotForm /></TabsContent>
          </Tabs>
        </Card>
        <p className="mt-4 text-center text-xs text-muted-foreground">
          Protected by Shahin Security. By continuing you agree to our Terms & Privacy.
        </p>
      </div>
    </div>
  );
}

function GoogleButton() {
  const [loading, setLoading] = useState(false);
  async function go() {
    setLoading(true);
    const res = await lovable.auth.signInWithOAuth("google", { redirect_uri: window.location.origin });
    if (res.error) { setLoading(false); toast.error("Google sign-in failed"); }
  }
  return (
    <Button type="button" variant="outline" className="w-full" onClick={go} disabled={loading}>
      {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <GoogleIcon />}
      Continue with Google
    </Button>
  );
}

function LoginForm() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const schema = z.object({ email: z.string().email(), password: z.string().min(6) });
    const parsed = schema.safeParse({ email: fd.get("email"), password: fd.get("password") });
    if (!parsed.success) { toast.error(parsed.error.issues[0].message); return; }
    setLoading(true);
    const { error } = await supabase.auth.signInWithPassword(parsed.data);
    setLoading(false);
    if (error) { toast.error(error.message); return; }
    toast.success("Welcome back");
    navigate({ to: "/dashboard" });
  }
  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <GoogleButton />
      <Divider />
      <Field name="email" label="Email" type="email" placeholder="you@company.com" />
      <Field name="password" label="Password" type="password" placeholder="••••••••" />
      <Button type="submit" className="w-full bg-gradient-primary text-primary-foreground" disabled={loading}>
        {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}Sign in
      </Button>
    </form>
  );
}

function RegisterForm() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const schema = z.object({
      full_name: z.string().trim().min(2).max(80),
      email: z.string().email(),
      password: z.string().min(8, "Use at least 8 characters"),
    });
    const parsed = schema.safeParse({
      full_name: fd.get("full_name"),
      email: fd.get("email"),
      password: fd.get("password"),
    });
    if (!parsed.success) { toast.error(parsed.error.issues[0].message); return; }
    setLoading(true);
    const { error } = await supabase.auth.signUp({
      email: parsed.data.email,
      password: parsed.data.password,
      options: {
        emailRedirectTo: window.location.origin,
        data: { full_name: parsed.data.full_name },
      },
    });
    setLoading(false);
    if (error) { toast.error(error.message); return; }
    toast.success("Account created");
    navigate({ to: "/dashboard" });
  }
  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <GoogleButton />
      <Divider />
      <Field name="full_name" label="Full name" placeholder="Ada Lovelace" />
      <Field name="email" label="Work email" type="email" placeholder="you@company.com" />
      <Field name="password" label="Password" type="password" placeholder="At least 8 characters" />
      <Button type="submit" className="w-full bg-gradient-primary text-primary-foreground" disabled={loading}>
        {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}Create account
      </Button>
    </form>
  );
}

function ForgotForm() {
  const [loading, setLoading] = useState(false);
  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const email = new FormData(e.currentTarget).get("email");
    const parsed = z.string().email().safeParse(email);
    if (!parsed.success) { toast.error("Enter a valid email"); return; }
    setLoading(true);
    const { error } = await supabase.auth.resetPasswordForEmail(parsed.data, {
      redirectTo: `${window.location.origin}/reset-password`,
    });
    setLoading(false);
    if (error) { toast.error(error.message); return; }
    toast.success("If an account exists, we sent a reset link");
  }
  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <p className="text-sm text-muted-foreground">Enter your email and we'll send you a reset link.</p>
      <Field name="email" label="Email" type="email" placeholder="you@company.com" />
      <Button type="submit" className="w-full" disabled={loading}>
        {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}Send reset link
      </Button>
    </form>
  );
}

function Field({ name, label, type = "text", placeholder }: { name: string; label: string; type?: string; placeholder?: string }) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={name}>{label}</Label>
      <Input id={name} name={name} type={type} placeholder={placeholder} required />
    </div>
  );
}

function Divider() {
  return (
    <div className="relative py-1 text-center">
      <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-border/60" /></div>
      <span className="relative bg-card px-2 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">or continue with email</span>
    </div>
  );
}

function GoogleIcon() {
  return (
    <svg className="mr-2 h-4 w-4" viewBox="0 0 24 24">
      <path fill="#EA4335" d="M12 10.2v3.9h5.5c-.24 1.4-1.7 4.1-5.5 4.1-3.3 0-6-2.7-6-6.2s2.7-6.2 6-6.2c1.9 0 3.1.8 3.8 1.5l2.6-2.5C16.7 3 14.6 2 12 2 6.9 2 2.8 6.1 2.8 12S6.9 22 12 22c6.9 0 9.5-4.9 9.5-8.5 0-.6 0-1-.1-1.3H12z" />
    </svg>
  );
}
