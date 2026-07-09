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
  evidence: string; // multi-line, monospace-friendly raw evidence
}

interface StepResult { key: string; ok: boolean; detail: string }

interface RedirectHop {
  url: string;
  status: number;
  location?: string;
}

interface CookieInfo {
  name: string;
  raw: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
}

interface TechHit { name: string; source: string; evidence: string }

interface ScanResult {
  score: number;
  risk: RiskLevel;
  findings: Finding[];
  steps: StepResult[];
  tech: TechHit[];
  target: {
    url: string;
    finalUrl: string;
    statusCode: number;
    protocol: string;
    hstsRedirect: boolean;
    server?: string;
    poweredBy?: string;
    responseHeaders: Record<string, string>;
    setCookies: CookieInfo[];
    redirectChain: RedirectHop[];
    httpToHttpsChain: RedirectHop[];
  };
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25, high: 15, medium: 8, low: 4, info: 1,
};

const SECURITY_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "cross-origin-embedder-policy",
  "server",
  "x-powered-by",
];

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

function parseCookie(raw: string): CookieInfo {
  const parts = raw.split(";").map((p) => p.trim());
  const [nameValue, ...attrs] = parts;
  const name = nameValue.split("=")[0] ?? "(unnamed)";
  const lowerAttrs = attrs.map((a) => a.toLowerCase());
  const sameSiteAttr = attrs.find((a) => a.toLowerCase().startsWith("samesite="));
  return {
    name,
    raw,
    secure: lowerAttrs.includes("secure"),
    httpOnly: lowerAttrs.includes("httponly"),
    sameSite: sameSiteAttr?.split("=")[1],
  };
}

function detectTech(headers: Headers, html: string): TechHit[] {
  const hits: TechHit[] = [];
  const push = (name: string, source: string, evidence: string) => {
    if (!hits.some((h) => h.name === name)) hits.push({ name, source, evidence });
  };
  const server = headers.get("server"); if (server) push(server, "header", `server: ${server}`);
  const xp = headers.get("x-powered-by"); if (xp) push(xp, "header", `x-powered-by: ${xp}`);
  const via = headers.get("via"); if (via) push(`Via ${via}`, "header", `via: ${via}`);
  if (headers.get("cf-ray")) push("Cloudflare", "header", `cf-ray: ${headers.get("cf-ray")}`);
  if (headers.get("x-vercel-id")) push("Vercel", "header", `x-vercel-id: ${headers.get("x-vercel-id")}`);
  if (headers.get("x-nf-request-id")) push("Netlify", "header", `x-nf-request-id: ${headers.get("x-nf-request-id")}`);
  const gen = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  if (gen) push(`Generator: ${gen[1]}`, "html", gen[0]);
  const patterns: [RegExp, string][] = [
    [/wp-content|wp-includes/i, "WordPress"],
    [/_next\/static/i, "Next.js"],
    [/window\.__NUXT__/i, "Nuxt"],
    [/id=["']__vite|\/@vite\//i, "Vite"],
    [/data-reactroot|react-dom/i, "React"],
    [/ng-version=/i, "Angular"],
    [/cdn\.shopify\.com|Shopify\.theme/i, "Shopify"],
    [/static1\.squarespace\.com/i, "Squarespace"],
    [/wix\.com|static\.parastorage\.com/i, "Wix"],
    [/webflow\.js/i, "Webflow"],
  ];
  for (const [re, name] of patterns) {
    const m = html.match(re);
    if (m) push(name, "html", `matched /${re.source}/ → "${m[0].slice(0, 80)}"`);
  }
  return hits;
}

function headersToRecord(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((v, k) => { out[k] = v; });
  return out;
}

async function followRedirects(startUrl: string, opts: RequestInit): Promise<{ chain: RedirectHop[]; final: Response }> {
  const chain: RedirectHop[] = [];
  let current = startUrl;
  for (let i = 0; i < 10; i++) {
    const r = await fetch(current, { ...opts, redirect: "manual" });
    const loc = r.headers.get("location");
    chain.push({ url: current, status: r.status, location: loc || undefined });
    if (r.status >= 300 && r.status < 400 && loc) {
      try { current = new URL(loc, current).toString(); } catch { return { chain, final: r }; }
      await r.body?.cancel();
      continue;
    }
    return { chain, final: r };
  }
  throw new Error("Too many redirects (>10)");
}

async function runRealScan(rawUrl: string): Promise<ScanResult> {
  const findings: Finding[] = [];
  const steps: StepResult[] = [];
  let url: URL;
  try { url = new URL(rawUrl); } catch { throw new Error("Invalid URL"); }

  // Step 1: HTTP→HTTPS redirect probe (only when target is https)
  let hstsRedirect = false;
  let httpToHttpsChain: RedirectHop[] = [];
  if (url.protocol === "https:") {
    try {
      const httpUrl = new URL(rawUrl); httpUrl.protocol = "http:";
      const probe = await followRedirects(httpUrl.toString(), {
        method: "GET",
        headers: { "user-agent": "SentraX-Scanner/1.0" },
        signal: AbortSignal.timeout(8000),
      });
      httpToHttpsChain = probe.chain;
      const finalUrlProbe = probe.chain.at(-1)?.url ?? httpUrl.toString();
      hstsRedirect = finalUrlProbe.startsWith("https://");
      if (!hstsRedirect) {
        findings.push({
          category: "ssl", severity: "medium",
          title: "HTTP does not redirect to HTTPS",
          description: "Plain HTTP requests are not redirected to HTTPS, allowing users to browse over an insecure channel.",
          recommendation: "Configure a permanent 301 redirect from http:// to https:// at the edge or web server.",
          evidence:
            `Probed: ${httpUrl.toString()}\n` +
            probe.chain.map((h, i) => `  [${i}] ${h.status} ${h.url}${h.location ? ` → ${h.location}` : ""}`).join("\n") +
            `\nFinal URL: ${finalUrlProbe}`,
        });
      }
    } catch (e) {
      httpToHttpsChain = [{ url: rawUrl.replace(/^https:/, "http:"), status: 0, location: e instanceof Error ? e.message : String(e) }];
    }
  } else {
    findings.push({
      category: "ssl", severity: "high",
      title: "Site not served over HTTPS",
      description: "The target URL uses HTTP. Traffic can be intercepted or tampered with by any network attacker.",
      recommendation: "Obtain a TLS certificate (Let's Encrypt) and force HTTPS on all endpoints.",
      evidence: `Requested URL protocol: ${url.protocol}\nHost: ${url.hostname}`,
    });
  }
  steps.push({ key: "website", ok: true, detail: `Analyzed ${url.hostname}` });

  // Step 2: main fetch with full redirect chain
  let response: Response;
  let html = "";
  let finalUrl = rawUrl;
  let statusCode = 0;
  let mainChain: RedirectHop[] = [];
  try {
    const { chain, final } = await followRedirects(rawUrl, {
      method: "GET",
      headers: { "user-agent": "SentraX-Scanner/1.0 (+https://sentrax.app)" },
      signal: AbortSignal.timeout(15000),
    });
    mainChain = chain;
    response = final;
    finalUrl = chain.at(-1)?.url ?? rawUrl;
    statusCode = final.status;
    const ct = final.headers.get("content-type") || "";
    if (ct.includes("text/") || ct.includes("html") || ct.includes("xml")) {
      html = (await final.text()).slice(0, 300_000);
    }
    steps.push({ key: "ssl", ok: url.protocol === "https:", detail: url.protocol === "https:" ? "TLS handshake succeeded" : "No TLS in use" });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    steps.push({ key: "ssl", ok: false, detail: `Fetch failed: ${msg}` });
    findings.push({
      category: "website", severity: "high",
      title: "Target unreachable",
      description: `The scanner could not connect to ${rawUrl}: ${msg}`,
      recommendation: "Verify the site is publicly reachable and not blocking the scanner's IP.",
      evidence: `GET ${rawUrl}\nError: ${msg}`,
    });
    const penalty = findings.reduce((a, f) => a + SEVERITY_WEIGHT[f.severity], 0);
    const score = Math.max(15, 100 - penalty);
    return {
      score, risk: score >= 80 ? "Low" : score >= 55 ? "Medium" : "High",
      findings, steps, tech: [],
      target: {
        url: rawUrl, finalUrl: rawUrl, statusCode: 0, protocol: url.protocol, hstsRedirect,
        responseHeaders: {}, setCookies: [], redirectChain: [], httpToHttpsChain,
      },
    };
  }

  // Step 3: security headers
  const h = response.headers;
  const headersRecord = headersToRecord(h);
  for (const rec of REC_HEADERS) {
    if (!h.get(rec.name)) {
      const present = SECURITY_HEADERS
        .filter((n) => h.get(n))
        .map((n) => `  ${n}: ${h.get(n)}`).join("\n") || "  (no other security headers set)";
      findings.push({
        category: "headers", severity: rec.severity,
        title: rec.title, description: rec.desc, recommendation: rec.rec,
        evidence:
          `Response from: ${finalUrl}\nStatus: ${statusCode}\nMissing header: ${rec.name}\n\nOther security headers seen:\n${present}`,
      });
    }
  }
  const server = h.get("server");
  if (server && /\d/.test(server)) {
    findings.push({
      category: "headers", severity: "low",
      title: "Server version disclosed in response header",
      description: `The 'Server' header reveals '${server}', aiding attacker reconnaissance for known CVEs.`,
      recommendation: "Suppress or generalize the Server header at the reverse proxy or web server.",
      evidence: `server: ${server}\nSource: ${finalUrl}`,
    });
  }
  const xpb = h.get("x-powered-by");
  if (xpb) {
    findings.push({
      category: "headers", severity: "low",
      title: "X-Powered-By header disclosed",
      description: `Header reveals backend stack: '${xpb}'.`,
      recommendation: "Remove the X-Powered-By header at the web server or framework config.",
      evidence: `x-powered-by: ${xpb}\nSource: ${finalUrl}`,
    });
  }
  steps.push({ key: "headers", ok: true, detail: `Inspected ${Object.keys(headersRecord).length} response headers` });

  // Step 4: cookies + tech
  // getSetCookie() is the standard way to get each Set-Cookie separately.
  const rawSetCookies: string[] =
    typeof (h as unknown as { getSetCookie?: () => string[] }).getSetCookie === "function"
      ? (h as unknown as { getSetCookie: () => string[] }).getSetCookie()
      : (h.get("set-cookie") ? [h.get("set-cookie")!] : []);
  const cookies: CookieInfo[] = rawSetCookies.map(parseCookie);

  const insecure = cookies.filter((c) => !c.secure);
  const noHttpOnly = cookies.filter((c) => !c.httpOnly);
  const noSameSite = cookies.filter((c) => !c.sameSite);
  if (insecure.length) {
    findings.push({
      category: "cookies", severity: "high",
      title: `${insecure.length} cookie${insecure.length === 1 ? "" : "s"} missing Secure flag`,
      description: "Cookies without the Secure attribute may be transmitted over unencrypted HTTP.",
      recommendation: "Add the Secure attribute to every cookie set on HTTPS responses.",
      evidence: insecure.map((c) => `${c.name}\n  raw: ${c.raw}`).join("\n\n"),
    });
  }
  if (noHttpOnly.length) {
    findings.push({
      category: "cookies", severity: "medium",
      title: `${noHttpOnly.length} cookie${noHttpOnly.length === 1 ? "" : "s"} missing HttpOnly flag`,
      description: "Cookies without HttpOnly are readable from JavaScript, increasing XSS impact for session tokens.",
      recommendation: "Set HttpOnly on all session/authentication cookies.",
      evidence: noHttpOnly.map((c) => `${c.name}\n  raw: ${c.raw}`).join("\n\n"),
    });
  }
  if (noSameSite.length) {
    findings.push({
      category: "cookies", severity: "low",
      title: `${noSameSite.length} cookie${noSameSite.length === 1 ? "" : "s"} missing SameSite attribute`,
      description: "Without SameSite, cookies may be sent in cross-site requests, enabling CSRF.",
      recommendation: "Set SameSite=Lax or SameSite=Strict on cookies.",
      evidence: noSameSite.map((c) => `${c.name}\n  raw: ${c.raw}`).join("\n\n"),
    });
  }

  const tech = detectTech(h, html);
  steps.push({ key: "tech", ok: true, detail: tech.length ? `Detected ${tech.length} technologies` : "No tech fingerprint found" });

  // Step 5: risk evaluation
  const penalty = findings.reduce((a, f) => a + SEVERITY_WEIGHT[f.severity], 0);
  const score = Math.max(10, Math.min(100, 100 - penalty));
  const risk: RiskLevel = score >= 80 ? "Low" : score >= 55 ? "Medium" : "High";
  steps.push({ key: "risk", ok: true, detail: `Score ${score}/100 • ${findings.length} findings` });

  return {
    score, risk, findings, steps, tech,
    target: {
      url: rawUrl, finalUrl, statusCode, protocol: url.protocol, hstsRedirect,
      server: server || undefined,
      poweredBy: xpb || undefined,
      responseHeaders: headersRecord,
      setCookies: cookies,
      redirectChain: mainChain,
      httpToHttpsChain,
    },
  };
}

export const runScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => z.object({ website: z.string().url() }).parse(data))
  .handler(async ({ data }): Promise<ScanResult> => {
    return await runRealScan(data.website);
  });
