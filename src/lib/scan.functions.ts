import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type RiskLevel = "Low" | "Medium" | "High";

export interface Finding {
  title: string;
  severity: Severity;
  description: string;
  recommendation: string;
  category: "headers" | "ssl" | "tech" | "cookies" | "website";
}

interface StepResult {
  key: string;
  ok: boolean;
  detail: string;
}

interface ScanResult {
  score: number;
  risk: RiskLevel;
  findings: Finding[];
  steps: StepResult[];
  tech: string[];
  target: {
    url: string;
    finalUrl: string;
    statusCode: number;
    server?: string;
    protocol: string;
    hstsRedirect: boolean;
  };
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25, high: 15, medium: 8, low: 4, info: 1,
};

const REC_HEADERS: {
  name: string; severity: Severity; title: string; desc: string; rec: string;
}[] = [
  { name: "content-security-policy", severity: "high", title: "Missing Content-Security-Policy header",
    desc: "No CSP is set. CSP is a strong defense-in-depth against XSS and data injection by restricting allowed sources.",
    rec: "Define a strict CSP restricting script-src, style-src, and frame-ancestors to trusted origins." },
  { name: "strict-transport-security", severity: "medium", title: "Missing Strict-Transport-Security (HSTS)",
    desc: "Without HSTS, browsers may accept an unencrypted connection first, enabling downgrade attacks.",
    rec: "Set 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' on all HTTPS responses." },
  { name: "x-frame-options", severity: "medium", title: "Missing X-Frame-Options / frame-ancestors",
    desc: "The page can be embedded in an iframe, enabling clickjacking.",
    rec: "Set 'X-Frame-Options: DENY' or CSP 'frame-ancestors none'." },
  { name: "x-content-type-options", severity: "low", title: "Missing X-Content-Type-Options",
    desc: "Browsers may MIME-sniff responses, enabling content-type confusion attacks.",
    rec: "Set 'X-Content-Type-Options: nosniff' globally." },
  { name: "referrer-policy", severity: "low", title: "Missing Referrer-Policy",
    desc: "Full referrer URLs may leak to third parties.",
    rec: "Set 'Referrer-Policy: strict-origin-when-cross-origin'." },
  { name: "permissions-policy", severity: "info", title: "Missing Permissions-Policy",
    desc: "Powerful browser features (camera, mic, geolocation) are not explicitly restricted.",
    rec: "Define a Permissions-Policy disabling unused features." },
];

function detectTech(headers: Headers, html: string): string[] {
  const tech = new Set<string>();
  const server = headers.get("server"); if (server) tech.add(`Server: ${server}`);
  const xp = headers.get("x-powered-by"); if (xp) tech.add(`X-Powered-By: ${xp}`);
  const via = headers.get("via"); if (via) tech.add(`Via: ${via}`);
  const cf = headers.get("cf-ray"); if (cf) tech.add("Cloudflare");
  const gen = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  if (gen) tech.add(`Generator: ${gen[1]}`);
  if (/wp-content|wp-includes/i.test(html)) tech.add("WordPress");
  if (/_next\/static/i.test(html)) tech.add("Next.js");
  if (/window\.__NUXT__/i.test(html)) tech.add("Nuxt");
  if (/id=["']__vite/i.test(html) || /\/@vite\//i.test(html)) tech.add("Vite");
  if (/data-reactroot|react-dom/i.test(html)) tech.add("React");
  if (/ng-version=/i.test(html)) tech.add("Angular");
  if (/shopify/i.test(html)) tech.add("Shopify");
  if (/squarespace/i.test(html)) tech.add("Squarespace");
  return [...tech];
}

async function runRealScan(rawUrl: string): Promise<ScanResult> {
  const findings: Finding[] = [];
  const steps: StepResult[] = [];
  let url: URL;
  try { url = new URL(rawUrl); } catch { throw new Error("Invalid URL"); }

  // Step 1: website reachability + HTTP→HTTPS redirect check
  let hstsRedirect = false;
  if (url.protocol === "https:") {
    try {
      const httpUrl = new URL(rawUrl); httpUrl.protocol = "http:";
      const r = await fetch(httpUrl.toString(), { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(8000) });
      const loc = r.headers.get("location") || "";
      hstsRedirect = r.status >= 300 && r.status < 400 && loc.startsWith("https://");
      if (!hstsRedirect) {
        findings.push({ category: "ssl", severity: "medium", title: "HTTP does not redirect to HTTPS",
          description: "Plain HTTP requests are not redirected to HTTPS, allowing users to browse over an insecure channel.",
          recommendation: "Configure a permanent 301 redirect from http:// to https:// at the edge or web server." });
      }
    } catch { /* http may be blocked entirely — that's fine */ }
  } else {
    findings.push({ category: "ssl", severity: "high", title: "Site not served over HTTPS",
      description: "The target URL uses HTTP. Traffic can be intercepted or tampered with by any network attacker.",
      recommendation: "Obtain a TLS certificate (Let's Encrypt) and force HTTPS on all endpoints." });
  }
  steps.push({ key: "website", ok: true, detail: `Analyzed ${url.hostname}` });

  // Step 2: SSL — via a real HTTPS fetch and cert info via SSL Labs-style endpoint (skip heavy call, use fetch success)
  let response: Response;
  let html = "";
  let finalUrl = rawUrl;
  let statusCode = 0;
  try {
    response = await fetch(rawUrl, {
      method: "GET",
      redirect: "follow",
      headers: { "user-agent": "SentraX-Scanner/1.0 (+https://sentrax.app)" },
      signal: AbortSignal.timeout(15000),
    });
    finalUrl = response.url || rawUrl;
    statusCode = response.status;
    const ct = response.headers.get("content-type") || "";
    if (ct.includes("text/") || ct.includes("html")) {
      html = (await response.text()).slice(0, 300_000);
    }
    steps.push({ key: "ssl", ok: url.protocol === "https:", detail: url.protocol === "https:" ? "TLS handshake succeeded" : "No TLS in use" });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    steps.push({ key: "ssl", ok: false, detail: `Fetch failed: ${msg}` });
    findings.push({ category: "website", severity: "high", title: "Target unreachable",
      description: `The scanner could not connect to ${rawUrl}: ${msg}`,
      recommendation: "Verify the site is publicly reachable and not blocking the scanner's IP." });
    // return early with a low-info result
    const penalty = findings.reduce((a, f) => a + SEVERITY_WEIGHT[f.severity], 0);
    const score = Math.max(15, 100 - penalty);
    return {
      score, risk: score >= 80 ? "Low" : score >= 55 ? "Medium" : "High",
      findings, steps, tech: [],
      target: { url: rawUrl, finalUrl: rawUrl, statusCode: 0, protocol: url.protocol, hstsRedirect },
    };
  }

  // Step 3: security headers
  const h = response.headers;
  for (const rec of REC_HEADERS) {
    if (!h.get(rec.name)) {
      findings.push({ category: "headers", severity: rec.severity, title: rec.title, description: rec.desc, recommendation: rec.rec });
    }
  }
  const server = h.get("server");
  if (server && /\d/.test(server)) {
    findings.push({ category: "headers", severity: "low", title: "Server version disclosed in response header",
      description: `The 'Server' header reveals '${server}', aiding attacker reconnaissance for known CVEs.`,
      recommendation: "Suppress or generalize the Server header at the reverse proxy or web server." });
  }
  const xpb = h.get("x-powered-by");
  if (xpb) {
    findings.push({ category: "headers", severity: "low", title: "X-Powered-By header disclosed",
      description: `Header reveals backend stack: '${xpb}'.`,
      recommendation: "Remove the X-Powered-By header at the web server or framework config." });
  }
  steps.push({ key: "headers", ok: true, detail: `Inspected ${[...h.keys()].length} response headers` });

  // Step 4: tech detection & cookies
  const tech = detectTech(h, html);
  const setCookies = h.get("set-cookie") || "";
  if (setCookies) {
    const lower = setCookies.toLowerCase();
    if (!lower.includes("secure")) {
      findings.push({ category: "cookies", severity: "high", title: "Cookies missing Secure flag",
        description: "One or more cookies were set without the Secure attribute and may be transmitted over HTTP.",
        recommendation: "Add the Secure attribute to all cookies set on HTTPS responses." });
    }
    if (!lower.includes("httponly")) {
      findings.push({ category: "cookies", severity: "medium", title: "Cookies missing HttpOnly flag",
        description: "Cookies without HttpOnly are readable from JavaScript, increasing XSS impact.",
        recommendation: "Set HttpOnly on all session/authentication cookies." });
    }
    if (!lower.includes("samesite")) {
      findings.push({ category: "cookies", severity: "low", title: "Cookies missing SameSite attribute",
        description: "Without SameSite, cookies may be sent in cross-site requests, enabling CSRF.",
        recommendation: "Set SameSite=Lax or SameSite=Strict on cookies." });
    }
  }
  steps.push({ key: "tech", ok: true, detail: tech.length ? `Detected ${tech.length} technologies` : "No tech fingerprint found" });

  // Step 5: risk evaluation
  const penalty = findings.reduce((a, f) => a + SEVERITY_WEIGHT[f.severity], 0);
  const score = Math.max(10, Math.min(100, 100 - penalty));
  const risk: RiskLevel = score >= 80 ? "Low" : score >= 55 ? "Medium" : "High";
  steps.push({ key: "risk", ok: true, detail: `Score ${score}/100 • ${findings.length} findings` });

  return {
    score, risk, findings, steps, tech,
    target: { url: rawUrl, finalUrl, statusCode, server: server || undefined, protocol: url.protocol, hstsRedirect },
  };
}

export const runScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => z.object({ website: z.string().url() }).parse(data))
  .handler(async ({ data }): Promise<ScanResult> => {
    return await runRealScan(data.website);
  });
