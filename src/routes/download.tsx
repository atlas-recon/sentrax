import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { SiteHeader } from "@/components/site-header";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Terminal, Download, ShieldCheck, Copy, Check, Cpu, Lock, Ban, MonitorSmartphone } from "lucide-react";
import { useDetectedOS, isLinuxDesktop } from "@/lib/platform";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/download")({
  head: () => ({
    meta: [
      { title: "Download SentraX for Linux — Athena OS & More" },
      { name: "description", content: "Install the SentraX penetration-testing GUI natively on Athena OS, Kali, Parrot, Arch, Debian and Fedora. No payment required on Linux." },
      { property: "og:title", content: "Download SentraX for Linux — Athena OS & More" },
      { property: "og:description", content: "Native Linux desktop build of the SentraX security assessment console. Free on Linux — every tool unlocked." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: DownloadPage,
});

const INSTALL_CMD = "curl -fsSL https://sentrax.lovable.app/downloads/install-sentrax.sh -o install-sentrax.sh && chmod +x install-sentrax.sh && ./install-sentrax.sh";

const DISTROS = [
  { name: "Athena OS", note: "Recommended — pentest-first Arch derivative" },
  { name: "Kali Linux", note: "Rolling / 2024+" },
  { name: "Parrot Security", note: "Security & Home editions" },
  { name: "Arch / BlackArch", note: "x86_64 & aarch64" },
  { name: "Debian / Ubuntu", note: "Debian 12+, Ubuntu 22.04+" },
  { name: "Fedora / RHEL", note: "Fedora 39+" },
];

function DownloadPage() {
  const os = useDetectedOS();
  const [copied, setCopied] = useState(false);
  const allowed = os !== null && isLinuxDesktop(os);

  function copy() {
    navigator.clipboard.writeText(INSTALL_CMD);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <SiteHeader />

      <section className="relative overflow-hidden bg-hero">
        <div className="absolute inset-0 grid-bg opacity-30" />
        <div className="relative mx-auto max-w-5xl px-4 py-20 text-center sm:px-6">
          <div className="mx-auto mb-6 inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-xs font-medium text-primary">
            <Terminal className="h-3.5 w-3.5" /> Linux desktop build
          </div>
          <h1 className="text-balance text-4xl font-bold tracking-tight sm:text-5xl">
            SentraX for <span className="text-gradient">Linux</span>
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-muted-foreground">
            The full penetration-testing GUI — same dashboard, same scanner, same OWASP reports —
            running natively on Athena OS and other Linux distributions.
            <span className="text-foreground"> Every tool is unlocked and there is no payment on Linux.</span>
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-4 py-14 sm:px-6">
        <Card className={cn("border-border/60 bg-gradient-card p-6", allowed && "ring-1 ring-primary/40 shadow-glow")}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="grid h-10 w-10 place-items-center rounded-md bg-primary/15 text-primary">
                <Download className="h-5 w-5" />
              </div>
              <div>
                <div className="font-semibold">SentraX Desktop 1.0 — Linux (x86_64 / arm64)</div>
                <div className="text-xs text-muted-foreground">
                  {os === null
                    ? "Detecting your operating system…"
                    : os === "athena"
                      ? "Athena OS detected — fully supported"
                      : allowed
                        ? "Linux detected — installation supported"
                        : "Your current system is not supported"}
                </div>
              </div>
            </div>
            {allowed && (
              <Button asChild className="bg-gradient-primary text-primary-foreground shadow-glow">
                <a href="/downloads/install-sentrax.sh" download>
                  <Download className="mr-2 h-4 w-4" /> Download installer
                </a>
              </Button>
            )}
          </div>

          {allowed ? (
            <div className="mt-6 space-y-4">
              <div className="rounded-lg border border-border/60 bg-background/50 p-4">
                <div className="mb-2 flex items-center justify-between text-xs text-muted-foreground">
                  <span className="font-mono">one-line install</span>
                  <button onClick={copy} className="inline-flex items-center gap-1 text-primary hover:underline">
                    {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                    {copied ? "Copied" : "Copy"}
                  </button>
                </div>
                <pre className="overflow-x-auto font-mono text-xs leading-relaxed text-foreground">{INSTALL_CMD}</pre>
              </div>
              <ol className="space-y-2 text-sm text-muted-foreground">
                <li><span className="font-mono text-primary">1.</span> Run the command above (or download the script and execute it).</li>
                <li><span className="font-mono text-primary">2.</span> The installer verifies you are on Linux, pulls the runtime and installs to <span className="font-mono">~/.local/share/sentrax</span>.</li>
                <li><span className="font-mono text-primary">3.</span> Launch with <span className="font-mono">sentrax</span> or from your application menu.</li>
              </ol>
            </div>
          ) : (
            <div className="mt-6 rounded-lg border border-destructive/40 bg-destructive/10 p-5">
              <div className="flex items-center gap-2 font-medium text-destructive">
                <Ban className="h-4 w-4" /> Linux only
              </div>
              <p className="mt-2 text-sm text-muted-foreground">
                The SentraX desktop build installs on Athena OS and other Linux distributions only.
                {os === "windows" && " Windows is not supported."}
                {os === "mac" && " macOS is not supported."}
                {os === "android" && " Android is not supported — use the installable web app instead."}
                {" "}You can keep using SentraX in the browser, or install it as a web app from the home page.
              </p>
              <Button asChild variant="outline" className="mt-4"><Link to="/">Back to SentraX web</Link></Button>
            </div>
          )}
        </Card>

        <div className="mt-10 grid gap-4 md:grid-cols-3">
          {[
            { icon: Lock, title: "No payment on Linux", body: "Pro and Business features are unlocked by default in the desktop build. No plans, no upgrade screens, no billing." },
            { icon: Cpu, title: "Full toolset", body: "OWASP Top 10 probes, SQLi/XSS checks, TLS, headers, cookies, DNS & email security, PDF reporting." },
            { icon: MonitorSmartphone, title: "Same interface", body: "Identical dashboard, assessment workflow, reports and profile customization as the web console." },
          ].map((f) => (
            <Card key={f.title} className="border-border/60 bg-gradient-card p-5">
              <f.icon className="h-5 w-5 text-primary" />
              <div className="mt-3 font-semibold">{f.title}</div>
              <p className="mt-1 text-sm text-muted-foreground">{f.body}</p>
            </Card>
          ))}
        </div>

        <div className="mt-10">
          <h2 className="text-lg font-semibold">Supported distributions</h2>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {DISTROS.map((d) => (
              <Card key={d.name} className="flex items-start gap-3 border-border/60 bg-gradient-card p-4">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                <div>
                  <div className="text-sm font-medium">{d.name}</div>
                  <div className="text-xs text-muted-foreground">{d.note}</div>
                </div>
              </Card>
            ))}
          </div>
          <p className="mt-4 text-xs text-muted-foreground">
            Requires <span className="font-mono">curl</span> and <span className="font-mono">unzip</span>. Uninstall any time with{" "}
            <span className="font-mono">rm -rf ~/.local/share/sentrax ~/.local/bin/sentrax ~/.local/share/applications/sentrax.desktop</span>.
          </p>
        </div>
      </section>
    </div>
  );
}
