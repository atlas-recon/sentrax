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
  category: "headers" | "ssl" | "tech" | "cookies" | "website" | "injection" | "xss" | "exposure" | "cors" | "redirect" | "content";
  owasp?: string; // e.g. "A03:2021 Injection"
  evidence: string;
}

interface StepResult { key: string; ok: boolean; detail: string }
interface RedirectHop { url: string; status: number; location?: string }
interface CookieInfo { name: string; raw: string; secure: boolean; httpOnly: boolean; sameSite?: string }
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
    probes: { path: string; status: number; note?: string }[];
  };
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 30, high: 18, medium: 9, low: 4, info: 1,
};

const SECURITY_HEADERS = [
  "content-security-policy", "strict-transport-security", "x-frame-options",
  "x-content-type-options", "referrer-policy", "permissions-policy",
  "cross-origin-opener-policy", "cross-origin-resource-policy", "cross-origin-embedder-policy",
  "server", "x-powered-by",
];

const REC_HEADERS: { name: string; severity: Severity; title: string; desc: string; rec: string; owasp: string }[] = [
  { name: "content-security-policy", severity: "high", owasp: "A05:2021 Security Misconfiguration",
    title: "Missing Content-Security-Policy header",
    desc: "No CSP is set. CSP is a strong defense-in-depth against XSS and data injection by restricting allowed sources.",
    rec: "Define a strict CSP restricting script-src, style-src, and frame-ancestors to trusted origins." },
  { name: "strict-transport-security", severity: "medium", owasp: "A02:2021 Cryptographic Failures",
    title: "Missing Strict-Transport-Security (HSTS)",
    desc: "Without HSTS, browsers may accept an unencrypted connection first, enabling downgrade attacks.",
    rec: "Set 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' on HTTPS responses." },
  { name: "x-frame-options", severity: "medium", owasp: "A05:2021 Security Misconfiguration",
    title: "Missing X-Frame-Options / frame-ancestors",
    desc: "The page can be embedded in an iframe, enabling clickjacking.",
    rec: "Set 'X-Frame-Options: DENY' or CSP 'frame-ancestors none'." },
  { name: "x-content-type-options", severity: "low", owasp: "A05:2021 Security Misconfiguration",
    title: "Missing X-Content-Type-Options",
    desc: "Browsers may MIME-sniff responses, enabling content-type confusion attacks.",
    rec: "Set 'X-Content-Type-Options: nosniff' globally." },
  { name: "referrer-policy", severity: "low", owasp: "A05:2021 Security Misconfiguration",
    title: "Missing Referrer-Policy",
    desc: "Full referrer URLs may leak to third parties.",
    rec: "Set 'Referrer-Policy: strict-origin-when-cross-origin'." },
  { name: "permissions-policy", severity: "info", owasp: "A05:2021 Security Misconfiguration",
    title: "Missing Permissions-Policy",
    desc: "Powerful browser features (camera, mic, geolocation) are not explicitly restricted.",
    rec: "Define a Permissions-Policy disabling unused features." },
];

function parseCookie(raw: string): CookieInfo {
  const parts = raw.split(";").map((p) => p.trim());
  const [nameValue, ...attrs] = parts;
  const name = nameValue.split("=")[0] ?? "(unnamed)";
  const lowerAttrs = attrs.map((a) => a.toLowerCase());
  const sameSiteAttr = attrs.find((a) => a.toLowerCase().startsWith("samesite="));
  return { name, raw, secure: lowerAttrs.includes("secure"), httpOnly: lowerAttrs.includes("httponly"), sameSite: sameSiteAttr?.split("=")[1] };
}

function detectTech(headers: Headers, html: string): TechHit[] {
  const hits: TechHit[] = [];
  const push = (name: string, source: string, evidence: string) => {
    if (!hits.some((h) => h.name === name)) hits.push({ name, source, evidence });
  };
  const server = headers.get("server"); if (server) push(server, "header", `server: ${server}`);
  const xp = headers.get("x-powered-by"); if (xp) push(xp, "header", `x-powered-by: ${xp}`);
  if (headers.get("cf-ray")) push("Cloudflare", "header", `cf-ray: ${headers.get("cf-ray")}`);
  if (headers.get("x-vercel-id")) push("Vercel", "header", `x-vercel-id: ${headers.get("x-vercel-id")}`);
  if (headers.get("x-nf-request-id")) push("Netlify", "header", `x-nf-request-id: ${headers.get("x-nf-request-id")}`);
  const gen = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  if (gen) push(`Generator: ${gen[1]}`, "html", gen[0]);
  const patterns: [RegExp, string][] = [
    [/wp-content|wp-includes/i, "WordPress"], [/_next\/static/i, "Next.js"],
    [/window\.__NUXT__/i, "Nuxt"], [/data-reactroot|react-dom/i, "React"],
    [/ng-version=/i, "Angular"], [/cdn\.shopify\.com/i, "Shopify"],
    [/wix\.com|static\.parastorage\.com/i, "Wix"], [/webflow\.js/i, "Webflow"],
    [/laravel_session/i, "Laravel"], [/csrfmiddlewaretoken/i, "Django"],
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

async function safeFetch(url: string, opts: RequestInit = {}): Promise<Response | null> {
  try {
    return await fetch(url, {
      redirect: "manual",
      headers: { "user-agent": "SentraX-Scanner/2.0" },
      signal: AbortSignal.timeout(8000),
      ...opts,
    });
  } catch { return null; }
}

// SQL error patterns (union of common DB error signatures)
const SQL_ERROR_PATTERNS = [
  /you have an error in your sql syntax/i, /warning:\s*mysql/i, /unclosed quotation mark after/i,
  /quoted string not properly terminated/i, /pg_query\(\)|pg_exec\(\)/i, /postgresql.*error/i,
  /ora-\d{5}/i, /sqlite3::sqlexception/i, /sqlstate\[/i, /odbc.*sql server/i,
  /microsoft ole db provider for sql server/i, /native client.*error/i,
];

// ---- DNS-over-HTTPS helper (Cloudflare) ----
async function dohQuery(name: string, type: string): Promise<string[]> {
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(6000),
    });
    if (!r.ok) return [];
    const j = await r.json() as { Answer?: { data: string }[] };
    return (j.Answer ?? []).map((a) => a.data.replace(/^"|"$/g, ""));
  } catch { return []; }
}

async function checkDnsAndEmail(host: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const apex = host.split(".").slice(-2).join(".");

  const [txt, dmarc, caa, dnskey, mx] = await Promise.all([
    dohQuery(apex, "TXT"),
    dohQuery(`_dmarc.${apex}`, "TXT"),
    dohQuery(apex, "CAA"),
    dohQuery(apex, "DNSKEY"),
    dohQuery(apex, "MX"),
  ]);

  const spf = txt.find((r) => /v=spf1/i.test(r));
  if (mx.length && !spf) {
    findings.push({
      category: "website", severity: "medium", owasp: "A07:2021 Identification & Auth Failures",
      title: "Missing SPF record",
      description: `The domain ${apex} has MX records but no SPF (v=spf1) TXT record. Attackers can spoof email from this domain.`,
      recommendation: `Publish an SPF record listing your legitimate mail sources, e.g. "v=spf1 include:_spf.google.com -all".`,
      evidence: `TXT ${apex}:\n${txt.length ? txt.map((t) => "  " + t).join("\n") : "  (no TXT records)"}\nMX ${apex}: ${mx.join(", ") || "none"}`,
    });
  } else if (spf && / \+all/i.test(spf)) {
    findings.push({
      category: "website", severity: "high", owasp: "A07:2021 Identification & Auth Failures",
      title: "SPF record allows any sender (+all)",
      description: "The SPF policy ends in '+all', permitting anyone to send email from this domain.",
      recommendation: "Change the SPF terminator to '-all' (hard fail) or at least '~all' (soft fail).",
      evidence: `SPF: ${spf}`,
    });
  }

  const dmarcRec = dmarc.find((r) => /v=DMARC1/i.test(r));
  if (mx.length && !dmarcRec) {
    findings.push({
      category: "website", severity: "medium", owasp: "A07:2021 Identification & Auth Failures",
      title: "Missing DMARC record",
      description: `No DMARC policy at _dmarc.${apex}. Without DMARC, spoofed email cannot be rejected reliably even with SPF/DKIM.`,
      recommendation: `Publish "v=DMARC1; p=reject; rua=mailto:dmarc@${apex}" and monitor reports, then tighten to p=reject.`,
      evidence: `TXT _dmarc.${apex}: ${dmarc.length ? dmarc.join(" | ") : "(none)"}`,
    });
  } else if (dmarcRec && /p=none/i.test(dmarcRec)) {
    findings.push({
      category: "website", severity: "low", owasp: "A07:2021 Identification & Auth Failures",
      title: "DMARC policy is monitor-only (p=none)",
      description: "DMARC is published but the policy is p=none, meaning failing messages are still delivered.",
      recommendation: "After reviewing aggregate reports, move to p=quarantine and then p=reject.",
      evidence: `DMARC: ${dmarcRec}`,
    });
  }

  if (caa.length === 0) {
    findings.push({
      category: "website", severity: "low", owasp: "A02:2021 Cryptographic Failures",
      title: "No CAA records",
      description: `The domain has no CAA record, so any Certificate Authority is allowed to issue a certificate for ${apex}. Attackers who compromise a CA (or a domain-validation channel) can silently issue valid certs.`,
      recommendation: `Publish a CAA record pinning your CA, e.g. "0 issue \"letsencrypt.org\"".`,
      evidence: `CAA ${apex}: (empty)`,
    });
  }

  if (dnskey.length === 0) {
    findings.push({
      category: "website", severity: "info", owasp: "A05:2021 Security Misconfiguration",
      title: "DNSSEC not enabled",
      description: "The domain has no DNSKEY record, so DNS responses are not cryptographically signed. Attackers on the network path can poison DNS responses.",
      recommendation: "Enable DNSSEC at your DNS provider / registrar and publish the DS record at the parent zone.",
      evidence: `DNSKEY ${apex}: (empty)`,
    });
  }

  return findings;
}

async function checkOwaspProbes(rawUrl: string, url: URL, html: string): Promise<{ findings: Finding[]; probes: { path: string; status: number; note?: string }[] }> {
  const findings: Finding[] = [];
  const probes: { path: string; status: number; note?: string }[] = [];
  const base = `${url.protocol}//${url.host}`;

  // ---- 1. Sensitive file exposure (A05 Misconfig / A01 Access Control) ----
  const sensitivePaths = [
    "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php.bak",
    "/config.json", "/backup.sql", "/server-status", "/phpinfo.php",
    "/.DS_Store", "/composer.json", "/package.json",
  ];
  for (const p of sensitivePaths) {
    const r = await safeFetch(base + p);
    if (!r) continue;
    probes.push({ path: p, status: r.status });
    if (r.status === 200) {
      const body = await r.text().catch(() => "");
      const snippet = body.slice(0, 200);
      const suspicious =
        (p === "/.env" && /=[^\n]/.test(snippet)) ||
        (p.startsWith("/.git/") && /ref:|repositoryformat/i.test(snippet)) ||
        (p === "/server-status" && /apache server status/i.test(snippet)) ||
        (p === "/phpinfo.php" && /phpinfo\(\)/i.test(snippet)) ||
        (p === "/.DS_Store" && body.length > 0) ||
        (p === "/composer.json" && /require/i.test(snippet)) ||
        (p === "/package.json" && /"dependencies"/i.test(snippet)) ||
        (p === "/backup.sql" && /insert into|create table/i.test(snippet));
      if (suspicious) {
        findings.push({
          category: "exposure", severity: p === "/.env" || p.startsWith("/.git/") || p === "/backup.sql" ? "critical" : "high",
          owasp: "A01:2021 Broken Access Control",
          title: `Sensitive file exposed: ${p}`,
          description: `The path ${p} is publicly reachable and returned recognizable sensitive content. Attackers use this to steal secrets, source code, or credentials.`,
          recommendation: `Block access to ${p} at the web server or CDN (deny rule, .htaccess, or CDN firewall). Remove the file from the deployed artifact.`,
          evidence: `GET ${base + p}\nStatus: ${r.status}\nBody snippet:\n${snippet}`,
        });
      }
    }
  }

  // ---- 2. Directory listing (A05) ----
  const dirProbe = await safeFetch(base + "/uploads/");
  if (dirProbe) {
    probes.push({ path: "/uploads/", status: dirProbe.status });
    if (dirProbe.status === 200) {
      const body = await dirProbe.text().catch(() => "");
      if (/<title>index of \//i.test(body) || /\[DIR\]/.test(body)) {
        findings.push({
          category: "exposure", severity: "medium",
          owasp: "A05:2021 Security Misconfiguration",
          title: "Directory listing enabled",
          description: "The server returns an auto-generated directory index for /uploads/, exposing file names to any visitor.",
          recommendation: "Disable Options +Indexes / autoindex at the web server. Return 403 or an empty index.html for directories.",
          evidence: `GET ${base}/uploads/\nStatus: 200\nBody starts with:\n${body.slice(0, 300)}`,
        });
      }
    }
  }

  // ---- 3. Reflected XSS probe (A03 Injection) ----
  // Only meaningful if URL has a query string OR we test the root with a canary
  const xssCanary = "sx" + Math.random().toString(36).slice(2, 8) + "<svg/onload=1>";
  const xssTestUrl = new URL(rawUrl);
  xssTestUrl.searchParams.set("q", xssCanary);
  const xssResp = await safeFetch(xssTestUrl.toString());
  if (xssResp) {
    probes.push({ path: `?q=<xss-canary>`, status: xssResp.status });
    const body = await xssResp.text().catch(() => "");
    if (body.includes(xssCanary)) {
      findings.push({
        category: "xss", severity: "high",
        owasp: "A03:2021 Injection",
        title: "Reflected input rendered without HTML encoding",
        description: "A canary payload sent in the query string was returned unencoded in the response body, indicating a reflected XSS sink.",
        recommendation: "HTML-encode all user input before writing it to responses. Prefer templating engines that auto-escape by default and enforce a strict CSP.",
        evidence: `Probe URL: ${xssTestUrl.toString()}\nCanary: ${xssCanary}\nReflected verbatim in response body.`,
      });
    } else if (body.includes(xssCanary.replace(/</g, "&lt;"))) {
      // properly encoded – no finding
    }
  }

  // ---- 4. SQL injection error-based probe (A03 Injection) ----
  const sqliUrl = new URL(rawUrl);
  sqliUrl.searchParams.set("id", "1'\"");
  const sqliResp = await safeFetch(sqliUrl.toString());
  if (sqliResp) {
    probes.push({ path: `?id=1'"`, status: sqliResp.status });
    const body = await sqliResp.text().catch(() => "");
    const match = SQL_ERROR_PATTERNS.find((re) => re.test(body));
    if (match) {
      findings.push({
        category: "injection", severity: "critical",
        owasp: "A03:2021 Injection",
        title: "SQL error revealed by tampered input",
        description: "Injecting a single quote into a query-string parameter produced a database error in the response, strongly suggesting a SQL injection sink.",
        recommendation: "Use parameterized queries / prepared statements everywhere. Never concatenate user input into SQL. Suppress verbose DB errors in production.",
        evidence: `Probe URL: ${sqliUrl.toString()}\nMatched pattern: /${match.source}/\nResponse status: ${sqliResp.status}`,
      });
    }
  }

  // ---- 5. Open redirect (A01 Broken Access / A10 SSRF-adjacent) ----
  const redirParams = ["url", "redirect", "next", "return", "returnUrl", "dest"];
  for (const key of redirParams) {
    const orUrl = new URL(rawUrl);
    orUrl.searchParams.set(key, "https://evil.example.com/pwn");
    const r = await safeFetch(orUrl.toString());
    if (!r) continue;
    if (r.status >= 300 && r.status < 400) {
      const loc = r.headers.get("location") || "";
      if (/^https?:\/\/evil\.example\.com/i.test(loc)) {
        findings.push({
          category: "redirect", severity: "high",
          owasp: "A01:2021 Broken Access Control",
          title: `Open redirect via ?${key}=`,
          description: `The endpoint redirects to an attacker-controlled URL supplied in ?${key}=. This enables phishing and OAuth-code theft.`,
          recommendation: "Validate redirect targets against an allowlist of known internal paths or domains. Reject absolute external URLs.",
          evidence: `Probe URL: ${orUrl.toString()}\nStatus: ${r.status}\nLocation: ${loc}`,
        });
        break;
      }
    }
  }

  // ---- 6. CORS misconfiguration (A05) ----
  const corsResp = await safeFetch(rawUrl, {
    headers: { origin: "https://evil.example.com", "user-agent": "SentraX-Scanner/2.0" },
  });
  if (corsResp) {
    const acao = corsResp.headers.get("access-control-allow-origin");
    const acac = corsResp.headers.get("access-control-allow-credentials");
    if (acao === "*" && acac === "true") {
      findings.push({
        category: "cors", severity: "high",
        owasp: "A05:2021 Security Misconfiguration",
        title: "CORS allows any origin with credentials",
        description: "The server returns 'Access-Control-Allow-Origin: *' together with 'Access-Control-Allow-Credentials: true' — a combination browsers reject for a reason: it would let any site read authenticated responses.",
        recommendation: "Echo only trusted origins in Access-Control-Allow-Origin, or drop credentials support.",
        evidence: `access-control-allow-origin: ${acao}\naccess-control-allow-credentials: ${acac}`,
      });
    } else if (acao === "https://evil.example.com") {
      findings.push({
        category: "cors", severity: "high",
        owasp: "A05:2021 Security Misconfiguration",
        title: "CORS reflects arbitrary Origin",
        description: "The server echoes the request's Origin header verbatim, effectively allowing any site to make authenticated requests to this origin.",
        recommendation: "Use a strict allowlist of trusted origins instead of reflecting the request Origin.",
        evidence: `Sent Origin: https://evil.example.com\nReceived access-control-allow-origin: ${acao}`,
      });
    }
  }

  // ---- 7. Mixed content (A02) ----
  if (url.protocol === "https:" && html) {
    const mixed = Array.from(html.matchAll(/(?:src|href)=["'](http:\/\/[^"']+)["']/gi))
      .map((m) => m[1])
      .filter((u) => !u.startsWith("http://localhost"))
      .slice(0, 10);
    if (mixed.length) {
      findings.push({
        category: "content", severity: "medium",
        owasp: "A02:2021 Cryptographic Failures",
        title: `Mixed content: ${mixed.length} insecure asset${mixed.length === 1 ? "" : "s"}`,
        description: "The HTTPS page loads sub-resources over plain HTTP. Browsers may block them or, worse, they can be tampered with in transit.",
        recommendation: "Rewrite asset URLs to https:// or protocol-relative //. Add 'Content-Security-Policy: upgrade-insecure-requests'.",
        evidence: mixed.map((u) => `  • ${u}`).join("\n"),
      });
    }
  }

  return { findings, probes };
}

async function runRealScan(rawUrl: string): Promise<ScanResult> {
  const findings: Finding[] = [];
  const steps: StepResult[] = [];
  let url: URL;
  try { url = new URL(rawUrl); } catch { throw new Error("Invalid URL"); }

  // Step 1: HTTP→HTTPS redirect probe
  let hstsRedirect = false;
  let httpToHttpsChain: RedirectHop[] = [];
  if (url.protocol === "https:") {
    try {
      const httpUrl = new URL(rawUrl); httpUrl.protocol = "http:";
      const probe = await followRedirects(httpUrl.toString(), {
        method: "GET",
        headers: { "user-agent": "SentraX-Scanner/2.0" },
        signal: AbortSignal.timeout(8000),
      });
      httpToHttpsChain = probe.chain;
      const finalUrlProbe = probe.chain.at(-1)?.url ?? httpUrl.toString();
      hstsRedirect = finalUrlProbe.startsWith("https://");
      if (!hstsRedirect) {
        findings.push({
          category: "ssl", severity: "medium", owasp: "A02:2021 Cryptographic Failures",
          title: "HTTP does not redirect to HTTPS",
          description: "Plain HTTP requests are not redirected to HTTPS, allowing users to browse over an insecure channel.",
          recommendation: "Configure a permanent 301 redirect from http:// to https:// at the edge or web server.",
          evidence: `Probed: ${httpUrl.toString()}\n` +
            probe.chain.map((h, i) => `  [${i}] ${h.status} ${h.url}${h.location ? ` → ${h.location}` : ""}`).join("\n") +
            `\nFinal URL: ${finalUrlProbe}`,
        });
      }
    } catch (e) {
      httpToHttpsChain = [{ url: rawUrl.replace(/^https:/, "http:"), status: 0, location: e instanceof Error ? e.message : String(e) }];
    }
  } else {
    findings.push({
      category: "ssl", severity: "high", owasp: "A02:2021 Cryptographic Failures",
      title: "Site not served over HTTPS",
      description: "The target URL uses HTTP. Traffic can be intercepted or tampered with by any network attacker.",
      recommendation: "Obtain a TLS certificate (Let's Encrypt) and force HTTPS on all endpoints.",
      evidence: `Requested URL protocol: ${url.protocol}\nHost: ${url.hostname}`,
    });
  }
  steps.push({ key: "website", ok: true, detail: `Analyzed ${url.hostname}` });

  // Step 2: main fetch
  let response: Response;
  let html = "";
  let finalUrl = rawUrl;
  let statusCode = 0;
  let mainChain: RedirectHop[] = [];
  try {
    const { chain, final } = await followRedirects(rawUrl, {
      method: "GET",
      headers: { "user-agent": "SentraX-Scanner/2.0 (+https://sentrax.app)" },
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
        responseHeaders: {}, setCookies: [], redirectChain: [], httpToHttpsChain, probes: [],
      },
    };
  }

  // Step 3: security headers
  const h = response.headers;
  const headersRecord = headersToRecord(h);
  for (const rec of REC_HEADERS) {
    if (!h.get(rec.name)) {
      const present = SECURITY_HEADERS.filter((n) => h.get(n)).map((n) => `  ${n}: ${h.get(n)}`).join("\n") || "  (no other security headers set)";
      findings.push({
        category: "headers", severity: rec.severity, owasp: rec.owasp,
        title: rec.title, description: rec.desc, recommendation: rec.rec,
        evidence: `Response from: ${finalUrl}\nStatus: ${statusCode}\nMissing header: ${rec.name}\n\nOther security headers seen:\n${present}`,
      });
    }
  }
  const server = h.get("server");
  if (server && /\d/.test(server)) {
    findings.push({
      category: "headers", severity: "low", owasp: "A05:2021 Security Misconfiguration",
      title: "Server version disclosed",
      description: `The 'Server' header reveals '${server}', aiding attacker reconnaissance for known CVEs.`,
      recommendation: "Suppress or generalize the Server header at the reverse proxy.",
      evidence: `server: ${server}\nSource: ${finalUrl}`,
    });
  }
  const xpb = h.get("x-powered-by");
  if (xpb) {
    findings.push({
      category: "headers", severity: "low", owasp: "A05:2021 Security Misconfiguration",
      title: "X-Powered-By header disclosed",
      description: `Header reveals backend stack: '${xpb}'.`,
      recommendation: "Remove the X-Powered-By header.",
      evidence: `x-powered-by: ${xpb}\nSource: ${finalUrl}`,
    });
  }
  steps.push({ key: "headers", ok: true, detail: `Inspected ${Object.keys(headersRecord).length} response headers` });

  // Step 4: cookies + tech
  const rawSetCookies: string[] =
    typeof (h as unknown as { getSetCookie?: () => string[] }).getSetCookie === "function"
      ? (h as unknown as { getSetCookie: () => string[] }).getSetCookie()
      : (h.get("set-cookie") ? [h.get("set-cookie")!] : []);
  const cookies: CookieInfo[] = rawSetCookies.map(parseCookie);

  const insecure = cookies.filter((c) => !c.secure);
  const noHttpOnly = cookies.filter((c) => !c.httpOnly);
  const noSameSite = cookies.filter((c) => !c.sameSite);
  if (insecure.length) findings.push({
    category: "cookies", severity: "high", owasp: "A02:2021 Cryptographic Failures",
    title: `${insecure.length} cookie(s) missing Secure flag`,
    description: "Cookies without Secure may be transmitted over plain HTTP.",
    recommendation: "Add the Secure attribute to every cookie set on HTTPS responses.",
    evidence: insecure.map((c) => `${c.name}\n  raw: ${c.raw}`).join("\n\n"),
  });
  if (noHttpOnly.length) findings.push({
    category: "cookies", severity: "medium", owasp: "A05:2021 Security Misconfiguration",
    title: `${noHttpOnly.length} cookie(s) missing HttpOnly flag`,
    description: "Cookies without HttpOnly are readable from JavaScript, amplifying XSS impact.",
    recommendation: "Set HttpOnly on session/auth cookies.",
    evidence: noHttpOnly.map((c) => `${c.name}\n  raw: ${c.raw}`).join("\n\n"),
  });
  if (noSameSite.length) findings.push({
    category: "cookies", severity: "low", owasp: "A01:2021 Broken Access Control",
    title: `${noSameSite.length} cookie(s) missing SameSite`,
    description: "Without SameSite, cookies may be sent in cross-site requests (CSRF risk).",
    recommendation: "Set SameSite=Lax or Strict.",
    evidence: noSameSite.map((c) => `${c.name}\n  raw: ${c.raw}`).join("\n\n"),
  });

  const tech = detectTech(h, html);
  steps.push({ key: "tech", ok: true, detail: tech.length ? `Detected ${tech.length} technologies` : "No tech fingerprint found" });

  // Step 5: OWASP active probes + DNS/email
  let probes: { path: string; status: number; note?: string }[] = [];
  try {
    const [owasp, dnsFindings] = await Promise.all([
      checkOwaspProbes(rawUrl, url, html),
      checkDnsAndEmail(url.hostname),
    ]);
    findings.push(...owasp.findings, ...dnsFindings);
    probes = owasp.probes;
  } catch { /* best-effort */ }

  const penalty = findings.reduce((a, f) => a + SEVERITY_WEIGHT[f.severity], 0);
  const score = Math.max(10, Math.min(100, 100 - penalty));
  const risk: RiskLevel = score >= 80 ? "Low" : score >= 55 ? "Medium" : "High";
  steps.push({ key: "risk", ok: true, detail: `Score ${score}/100 • ${findings.length} findings` });

  return {
    score, risk, findings, steps, tech,
    target: {
      url: rawUrl, finalUrl, statusCode, protocol: url.protocol, hstsRedirect,
      server: server || undefined, poweredBy: xpb || undefined,
      responseHeaders: headersRecord, setCookies: cookies,
      redirectChain: mainChain, httpToHttpsChain, probes,
    },
  };
}

export const runScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => z.object({ website: z.string().url() }).parse(data))
  .handler(async ({ data }): Promise<ScanResult> => runRealScan(data.website));
