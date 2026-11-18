import { Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Menu, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Logo } from "@/components/logo";
import { supabase } from "@/integrations/supabase/client";

const nav = [
  { href: "/#services", label: "Services" },
  { href: "/#how", label: "How it works" },
  { href: "/#pricing", label: "Pricing" },
  { href: "/#about", label: "About" },
  { href: "/sponsors", label: "Partners" },
  { href: "/#contact", label: "Contact" },
];

export function SiteHeader() {
  const [authed, setAuthed] = useState(false);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    supabase.auth.getUser().then(({ data }) => setAuthed(!!data.user));
    const { data: sub } = supabase.auth.onAuthStateChange((_, s) => setAuthed(!!s));
    return () => sub.subscription.unsubscribe();
  }, []);

  return (
    <header className="sticky top-0 z-40 border-b border-sidebar-border bg-navy/85 text-sidebar-accent-foreground backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6">
        <Link to="/" className="flex items-center"><Logo /></Link>
        <nav className="hidden items-center gap-7 lg:flex">
          {nav.map((n) => (
            <a key={n.href} href={n.href} className="text-sm font-medium text-sidebar-foreground transition-colors hover:text-cyan">
              {n.label}
            </a>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          {authed ? (
            <Button asChild size="sm"><Link to="/dashboard">Dashboard</Link></Button>
          ) : (
            <>
              <Button asChild size="sm" variant="ghost" className="hidden text-sidebar-foreground hover:bg-midnight hover:text-cyan sm:inline-flex"><Link to="/auth">Sign in</Link></Button>
              <Button asChild size="sm">
                <Link to="/auth" search={{ mode: "register" }}>Get started</Link>
              </Button>
            </>
          )}
          <button aria-label="Menu" onClick={() => setOpen(!open)} className="rounded-md p-2 text-sidebar-foreground lg:hidden">
            {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>
      </div>
      {open && (
        <nav className="border-t border-sidebar-border px-4 py-3 lg:hidden">
          {nav.map((n) => (
            <a key={n.href} href={n.href} onClick={() => setOpen(false)} className="block py-2 text-sm text-sidebar-foreground hover:text-cyan">{n.label}</a>
          ))}
          {!authed && <Link to="/auth" className="block py-2 text-sm text-sidebar-foreground">Sign in</Link>}
        </nav>
      )}
    </header>
  );
}
