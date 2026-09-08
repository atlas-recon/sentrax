import { Link, useRouterState, useNavigate } from "@tanstack/react-router";
import { LayoutDashboard, ShieldAlert, FileText, User, LogOut, Plus, Sparkles } from "lucide-react";
import { Logo } from "@/components/logo";
import { Button } from "@/components/ui/button";
import { supabase } from "@/integrations/supabase/client";
import { useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { ScanCreditsInline } from "@/components/scan-credits";


const items = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/assessments/new", label: "New Assessment", icon: Plus },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/profile", label: "Profile", icon: User },
] as const;

const upgradeItem = { to: "/upgrade", label: "Upgrade", icon: Sparkles } as const;

export function AppShell({ children, title, actions }: { children: ReactNode; title: string; actions?: ReactNode }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const navigate = useNavigate();
  const qc = useQueryClient();
  const desktop = useIsDesktopApp();
  const navItems = desktop ? items : [...items, upgradeItem];

  async function signOut() {
    await qc.cancelQueries();
    qc.clear();
    await supabase.auth.signOut();
    navigate({ to: "/auth", replace: true });
  }

  return (
    <div className="flex min-h-screen w-full bg-background text-foreground">
      <aside className="hidden w-64 shrink-0 flex-col border-r border-sidebar-border bg-sidebar md:flex">
        <div className="flex h-16 items-center border-b border-sidebar-border px-5">
          <Link to="/"><Logo /></Link>
        </div>
        <nav className="flex-1 space-y-1 p-3">
          {navItems.map((it) => {
            const active = pathname === it.to || (it.to !== "/dashboard" && pathname.startsWith(it.to));
            const Icon = it.icon;
            return (
              <Link
                key={it.to}
                to={it.to}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-sidebar-accent text-sidebar-accent-foreground shadow-glow"
                    : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground",
                )}
              >
                <Icon className="h-4 w-4" />
                {it.label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-sidebar-border p-3">
          <Button variant="ghost" className="w-full justify-start text-muted-foreground" onClick={signOut}>
            <LogOut className="mr-2 h-4 w-4" /> Sign out
          </Button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 border-b border-border/60 bg-background/70 backdrop-blur-xl">
          <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 px-4 py-4 sm:flex sm:px-6">
            <div className="flex min-w-0 items-center gap-3">
              <div className="md:hidden"><Logo showText={false} /></div>
              <h1 className="truncate text-lg font-semibold sm:text-xl">{title}</h1>
              <div className="hidden items-center gap-1.5 sm:flex">
                <span className="h-2 w-2 rounded-full bg-success animate-pulse-glow" />
                <span className="font-mono text-xs text-muted-foreground">SOC ONLINE</span>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="hidden md:inline-flex"><ScanCreditsInline /></span>
              <PwaInstallButton />
              {actions}
            </div>
          </div>
          <nav className="flex gap-1 overflow-x-auto border-t border-border/60 px-2 py-2 md:hidden">
            {navItems.map((it) => {
              const active = pathname === it.to || (it.to !== "/dashboard" && pathname.startsWith(it.to));
              return (
                <Link key={it.to} to={it.to} className={cn("shrink-0 rounded-md px-3 py-1.5 text-xs", active ? "bg-accent text-accent-foreground" : "text-muted-foreground")}>
                  {it.label}
                </Link>
              );
            })}
          </nav>
        </header>
        <main className="flex-1 p-4 sm:p-6">{children}</main>
      </div>
    </div>
  );
}
