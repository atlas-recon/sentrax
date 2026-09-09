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
  category:
    | "headers" | "ssl" | "tech" | "cookies" | "website" | "injection" | "xss"
    | "exposure" | "cors" | "redirect" | "content"
    | "dns" | "email" | "api" | "cms" | "privacy" | "infra" | "auth";
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

  // ---- 8. HTTP TRACE method enabled (A05) ----
  const traceResp = await safeFetch(rawUrl, { method: "TRACE" });
  if (traceResp) {
    probes.push({ path: "TRACE /", status: traceResp.status });
    if (traceResp.status === 200) {
      findings.push({
        category: "headers", severity: "medium", owasp: "A05:2021 Security Misconfiguration",
        title: "HTTP TRACE method enabled",
        description: "The server responds to TRACE requests, which can be abused in Cross-Site Tracing (XST) attacks to steal cookies protected by HttpOnly.",
        recommendation: "Disable TRACE at the web server (`TraceEnable Off` in Apache, drop the method in nginx/edge).",
        evidence: `TRACE ${rawUrl}\nStatus: ${traceResp.status}`,
      });
    }
  }

  // ---- 9. Exposed admin panels (A01) ----
  const adminPaths = ["/admin", "/admin/", "/wp-admin/", "/administrator/", "/phpmyadmin/", "/.well-known/security.txt"];
  for (const p of adminPaths) {
    const r = await safeFetch(base + p);
    if (!r) continue;
    probes.push({ path: p, status: r.status });
    if (p === "/.well-known/security.txt") {
      if (r.status === 404) {
        findings.push({
          category: "exposure", severity: "info", owasp: "A05:2021 Security Misconfiguration",
          title: "No security.txt disclosure policy",
          description: "The site does not publish /.well-known/security.txt, so security researchers have no standard channel to report vulnerabilities.",
          recommendation: "Publish a security.txt with a Contact: mailto: and Expires: date per RFC 9116.",
          evidence: `GET ${base}/.well-known/security.txt\nStatus: 404`,
        });
      }
      continue;
    }
    if (r.status === 200) {
      const body = await r.text().catch(() => "");
      if (/login|password|username|sign in/i.test(body)) {
        findings.push({
          category: "exposure", severity: "medium", owasp: "A01:2021 Broken Access Control",
          title: `Admin interface reachable at ${p}`,
          description: `The path ${p} returns a login page publicly. Brute-force and credential-stuffing attackers scan for exactly these endpoints.`,
          recommendation: `Restrict ${p} to VPN / office IPs, add MFA, and rate-limit login attempts.`,
          evidence: `GET ${base + p}\nStatus: 200\nMatches: login form keywords`,
        });
      }
    }
  }

  // ---- 10. Missing Subresource Integrity on cross-origin scripts (A08) ----
  if (html) {
    const scripts = Array.from(html.matchAll(/<script[^>]+src=["']([^"']+)["'][^>]*>/gi));
    const external = scripts.filter((m) => /^https?:\/\//i.test(m[1]) && !m[1].includes(url.hostname));
    const withoutSri = external.filter((m) => !/integrity=["']/i.test(m[0]));
    if (withoutSri.length) {
      findings.push({
        category: "content", severity: "low", owasp: "A08:2021 Software & Data Integrity Failures",
        title: `${withoutSri.length} external script(s) missing Subresource Integrity`,
        description: "Third-party scripts are loaded without `integrity=\"sha384-...\"`. If the CDN is compromised, attackers can inject malicious code with no browser check.",
        recommendation: "Add SRI hashes to all cross-origin <script> and <link rel=\"stylesheet\"> tags. Pin exact versions.",
        evidence: withoutSri.slice(0, 5).map((m) => `  • ${m[1]}`).join("\n"),
      });
    }
  }

  return { findings, probes };
}

// ============================================================================
// DEEP CHECKS — policy quality, API/CMS surface, infrastructure, privacy
// ============================================================================

/** Quality analysis of CSP / HSTS / Permissions-Policy values (not just presence). */
function analyzePolicyQuality(h: Headers, finalUrl: string): Finding[] {
  const out: Finding[] = [];
  const csp = h.get("content-security-policy");
  if (csp) {
    const lower = csp.toLowerCase();
    const weak: string[] = [];
    if (lower.includes("'unsafe-inline'")) weak.push("'unsafe-inline' allows inline scripts/styles — defeats most XSS protection");
    if (lower.includes("'unsafe-eval'")) weak.push("'unsafe-eval' permits eval()/new Function() on attacker-controlled strings");
    if (/(script-src|default-src)[^;]*\*/.test(lower)) weak.push("wildcard (*) source in script-src/default-src");
    if (/https?:(\s|;|$)/.test(lower)) weak.push("bare http:/https: scheme source allows any host");
    if (!lower.includes("object-src")) weak.push("no object-src — legacy plugin injection is not blocked");
    if (!lower.includes("frame-ancestors")) weak.push("no frame-ancestors — clickjacking not blocked by CSP");
    if (!lower.includes("base-uri")) weak.push("no base-uri — <base> tag injection can hijack relative script URLs");
    if (weak.length) {
      out.push({
        category: "headers", severity: weak.length >= 3 ? "high" : "medium",
        owasp: "A05:2021 Security Misconfiguration",
        title: `Weak Content-Security-Policy (${weak.length} issue${weak.length === 1 ? "" : "s"})`,
        description: "A CSP is present but contains directives that substantially reduce or nullify its protection against cross-site scripting and injection.",
        recommendation: "Remove 'unsafe-inline'/'unsafe-eval' (use nonces or hashes), replace wildcards with explicit origins, and add object-src 'none', base-uri 'self' and frame-ancestors 'none'.",
        evidence: `content-security-policy: ${csp}\n\nIssues:\n${weak.map((w) => "  • " + w).join("\n")}`,
      });
    }
  }

  const hsts = h.get("strict-transport-security");
  if (hsts) {
    const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0);
    const issues: string[] = [];
    if (maxAge < 15552000) issues.push(`max-age=${maxAge} is below the recommended 15552000 (180 days)`);
    if (!/includesubdomains/i.test(hsts)) issues.push("includeSubDomains missing — subdomains can still be downgraded to HTTP");
    if (!/preload/i.test(hsts)) issues.push("not preload-eligible — the very first visit is unprotected");
    if (issues.length) {
      out.push({
        category: "ssl", severity: maxAge < 86400 ? "medium" : "low",
        owasp: "A02:2021 Cryptographic Failures",
        title: "Weak HSTS configuration",
        description: "HSTS is enabled but configured too loosely to fully prevent HTTPS-downgrade and cookie-hijacking attacks.",
        recommendation: 'Use "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" once all subdomains serve HTTPS.',
        evidence: `strict-transport-security: ${hsts}\nSource: ${finalUrl}\n\nIssues:\n${issues.map((i) => "  • " + i).join("\n")}`,
      });
    }
  }

  const xfo = h.get("x-frame-options");
  if (xfo && /allow-from/i.test(xfo)) {
    out.push({
      category: "headers", severity: "low", owasp: "A05:2021 Security Misconfiguration",
      title: "Obsolete X-Frame-Options ALLOW-FROM directive",
      description: "ALLOW-FROM is ignored by all modern browsers, so this page is effectively framable.",
      recommendation: "Replace with CSP frame-ancestors, e.g. \"frame-ancestors 'self'\".",
      evidence: `x-frame-options: ${xfo}`,
    });
  }

  if (!h.get("cross-origin-opener-policy")) {
    out.push({
      category: "headers", severity: "low", owasp: "A05:2021 Security Misconfiguration",
      title: "Missing Cross-Origin-Opener-Policy",
      description: "Without COOP, a page you open (or that opens you) shares a browsing-context group, enabling cross-window scripting and Spectre-style side-channel attacks.",
      recommendation: 'Set "Cross-Origin-Opener-Policy: same-origin" on HTML responses.',
      evidence: `Response from: ${finalUrl}\ncross-origin-opener-policy: — not set`,
    });
  }

  const cache = h.get("cache-control") || "";
  if (h.get("set-cookie") && !/no-store|private/i.test(cache)) {
    out.push({
      category: "headers", severity: "medium", owasp: "A05:2021 Security Misconfiguration",
      title: "Session response is cacheable by shared caches",
      description: "The response sets cookies but does not forbid shared caching. A CDN or proxy can store and replay one user's personalised page to another user.",
      recommendation: 'Send "Cache-Control: no-store" (or at minimum "private, no-cache") on any authenticated or cookie-setting response.',
      evidence: `set-cookie: present\ncache-control: ${cache || "— not set"}\nSource: ${finalUrl}`,
    });
  }
  return out;
}

/** Deeper cookie hygiene beyond Secure/HttpOnly/SameSite presence. */
function analyzeCookieQuality(cookies: CookieInfo[]): Finding[] {
  const out: Finding[] = [];
  const noneNotSecure = cookies.filter((c) => c.sameSite?.toLowerCase() === "none" && !c.secure);
  if (noneNotSecure.length) {
    out.push({
      category: "cookies", severity: "high", owasp: "A05:2021 Security Misconfiguration",
      title: `${noneNotSecure.length} cookie(s) use SameSite=None without Secure`,
      description: "Browsers reject SameSite=None cookies that are not Secure, so these cookies are dropped or sent cross-site in clear text.",
      recommendation: "Always pair SameSite=None with the Secure attribute.",
      evidence: noneNotSecure.map((c) => `${c.name}\n  raw: ${c.raw}`).join("\n\n"),
    });
  }
  const sessionish = cookies.filter((c) => /sess|auth|token|jwt|sid|login/i.test(c.name));
  const unprefixed = sessionish.filter((c) => !/^__(Host|Secure)-/.test(c.name));
  if (unprefixed.length) {
    out.push({
      category: "cookies", severity: "low", owasp: "A01:2021 Broken Access Control",
      title: `${unprefixed.length} session cookie(s) without __Host-/__Secure- prefix`,
      description: "Cookie prefixes let the browser enforce that a session cookie was set over HTTPS from this exact host. Without them, a compromised subdomain can overwrite the session cookie (cookie tossing).",
      recommendation: "Rename session cookies to __Host-<name> and set them with Secure; Path=/; and no Domain attribute.",
      evidence: unprefixed.map((c) => `${c.name}\n  raw: ${c.raw}`).join("\n\n"),
    });
  }
  const longLived = cookies.filter((c) => {
    const m = /max-age=(\d+)/i.exec(c.raw);
    return m && Number(m[1]) > 60 * 60 * 24 * 365;
  });
  if (longLived.length) {
    out.push({
      category: "cookies", severity: "low", owasp: "A07:2021 Identification & Auth Failures",
      title: `${longLived.length} cookie(s) live longer than a year`,
      description: "Very long cookie lifetimes extend the window in which a stolen cookie remains valid and raise GDPR/ePrivacy consent questions.",
      recommendation: "Cap session cookies to hours, and persistent preference cookies to 6-13 months.",
      evidence: longLived.map((c) => `${c.name}\n  raw: ${c.raw}`).join("\n\n"),
    });
  }
  return out;
}

/** Known-vulnerable / outdated front-end libraries pulled from the HTML. */
function analyzeLibraries(html: string): Finding[] {
  if (!html) return [];
  const out: Finding[] = [];
  const rules: { name: string; re: RegExp; safeMajor: number; safeMinor: number; note: string }[] = [
    { name: "jQuery", re: /jquery[-.](\d+)\.(\d+)(?:\.(\d+))?(?:\.min)?\.js/i, safeMajor: 3, safeMinor: 5, note: "jQuery < 3.5 is affected by XSS via htmlPrefilter (CVE-2020-11022/11023)." },
    { name: "AngularJS", re: /angular[-.](1)\.(\d+)(?:\.(\d+))?(?:\.min)?\.js/i, safeMajor: 99, safeMinor: 0, note: "AngularJS 1.x reached end-of-life in 2022 and receives no security patches." },
    { name: "Bootstrap", re: /bootstrap[-.](\d+)\.(\d+)(?:\.(\d+))?(?:\.min)?\.(?:js|css)/i, safeMajor: 4, safeMinor: 3, note: "Bootstrap < 4.3.1 has XSS issues in tooltip/popover data attributes." },
    { name: "Lodash", re: /lodash[-.](\d+)\.(\d+)(?:\.(\d+))?(?:\.min)?\.js/i, safeMajor: 4, safeMinor: 17, note: "Lodash < 4.17.21 is vulnerable to prototype pollution / ReDoS." },
    { name: "Moment.js", re: /moment[-.](\d+)\.(\d+)(?:\.(\d+))?(?:\.min)?\.js/i, safeMajor: 2, safeMinor: 29, note: "Moment.js < 2.29.4 has a path-traversal/ReDoS advisory and the project is deprecated." },
  ];
  for (const r of rules) {
    const m = r.re.exec(html);
    if (!m) continue;
    const major = Number(m[1]); const minor = Number(m[2]);
    const outdated = major < r.safeMajor || (major === r.safeMajor && minor < r.safeMinor);
    if (outdated) {
      out.push({
        category: "tech", severity: "medium", owasp: "A06:2021 Vulnerable & Outdated Components",
        title: `Outdated ${r.name} ${major}.${minor}${m[3] ? "." + m[3] : ""} in use`,
        description: `${r.note} Attackers scan for library versions and reuse public exploits with no effort.`,
        recommendation: `Upgrade ${r.name} to a current release and add it to a dependency-monitoring workflow (Dependabot, Renovate, npm audit).`,
        evidence: `Matched asset reference in HTML:\n  ${m[0]}`,
      });
    }
  }
  return out;
}

/** Login/auth form hygiene and third-party tracking exposure. */
function analyzeFormsAndPrivacy(html: string, url: URL): Finding[] {
  if (!html) return [];
  const out: Finding[] = [];
  const forms = Array.from(html.matchAll(/<form[\s\S]{0,2000}?<\/form>/gi)).map((m) => m[0]);
  const pwForms = forms.filter((f) => /type=["']password["']/i.test(f));

  const getForms = pwForms.filter((f) => /method=["']get["']/i.test(f));
  if (getForms.length) {
    out.push({
      category: "auth", severity: "high", owasp: "A07:2021 Identification & Auth Failures",
      title: "Password form submits via GET",
      description: "Credentials submitted with GET end up in the URL, browser history, proxy logs and Referer headers.",
      recommendation: 'Use method="POST" over HTTPS for every credential form.',
      evidence: getForms[0].slice(0, 400),
    });
  }
  const httpAction = pwForms.filter((f) => /action=["']http:\/\//i.test(f));
  if (httpAction.length) {
    out.push({
      category: "auth", severity: "critical", owasp: "A02:2021 Cryptographic Failures",
      title: "Password form posts to an insecure http:// endpoint",
      description: "Credentials are transmitted unencrypted and can be captured by anyone on the network path.",
      recommendation: "Point the form action at an https:// URL and force TLS server-side.",
      evidence: httpAction[0].slice(0, 400),
    });
  }
  if (pwForms.length && !/csrf|authenticity_token|_token|xsrf/i.test(pwForms.join(" "))) {
    out.push({
      category: "auth", severity: "medium", owasp: "A01:2021 Broken Access Control",
      title: "Login form has no visible anti-CSRF token",
      description: "No hidden CSRF/anti-forgery token was found in the credential form. Where the framework does not add one automatically, this enables cross-site request forgery on authentication actions.",
      recommendation: "Emit a per-session anti-CSRF token in every state-changing form and validate it server-side; also set SameSite=Lax on session cookies.",
      evidence: pwForms[0].slice(0, 400),
    });
  }

  const trackers = [
    { name: "Google Analytics / GTM", re: /googletagmanager\.com|google-analytics\.com/i },
    { name: "Meta (Facebook) Pixel", re: /connect\.facebook\.net/i },
    { name: "TikTok Pixel", re: /analytics\.tiktok\.com/i },
    { name: "Hotjar", re: /static\.hotjar\.com/i },
    { name: "LinkedIn Insight", re: /snap\.licdn\.com/i },
  ].filter((t) => t.re.test(html));
  if (trackers.length) {
    out.push({
      category: "privacy", severity: "info", owasp: "A09:2021 Security Logging & Monitoring Failures",
      title: `${trackers.length} third-party tracker(s) loaded on the landing page`,
      description: `Detected: ${trackers.map((t) => t.name).join(", ")}. These scripts run with full page privileges and set cookies; under GDPR/ePrivacy they normally require prior consent.`,
      recommendation: "Load trackers only after explicit consent, restrict them in your CSP, and document them in your privacy notice and data-processing records.",
      evidence: trackers.map((t) => `  • ${t.name}`).join("\n"),
    });
  }

  const externalHosts = Array.from(new Set(
    Array.from(html.matchAll(/<script[^>]+src=["'](https?:\/\/[^"']+)["']/gi))
      .map((m) => { try { return new URL(m[1]).hostname; } catch { return ""; } })
      .filter((hst) => hst && hst !== url.hostname),
  ));
  if (externalHosts.length >= 5) {
    out.push({
      category: "content", severity: "low", owasp: "A08:2021 Software & Data Integrity Failures",
      title: `Large third-party script surface (${externalHosts.length} external origins)`,
      description: "Every external origin that serves JavaScript can read and modify the whole page. A single compromised vendor becomes a compromise of your site (Magecart-style supply-chain attack).",
      recommendation: "Reduce vendors, self-host critical scripts, add Subresource Integrity, and lock script-src in your CSP to an allow-list.",
      evidence: externalHosts.slice(0, 15).map((hst) => "  • " + hst).join("\n"),
    });
  }
  return out;
}

/** API surface, CMS surface, infrastructure and error-handling probes. */
async function checkDeepSurface(url: URL, html: string, tech: TechHit[]): Promise<{ findings: Finding[]; probes: { path: string; status: number; note?: string }[] }> {
  const findings: Finding[] = [];
  const probes: { path: string; status: number; note?: string }[] = [];
  const base = `${url.protocol}//${url.host}`;
  const note = (p: string, s: number, n?: string) => probes.push({ path: p, status: s, note: n });

  // ---- API documentation & management endpoints ----
  const apiPaths = [
    "/swagger.json", "/openapi.json", "/v2/api-docs", "/swagger-ui.html",
    "/actuator/env", "/actuator/health", "/api-docs", "/.well-known/security.txt",
  ];
  for (const p of apiPaths) {
    if (p === "/.well-known/security.txt") continue;
    const r = await safeFetch(base + p);
    if (!r) continue;
    note(p, r.status);
    if (r.status !== 200) { await r.body?.cancel(); continue; }
    const body = (await r.text().catch(() => "")).slice(0, 400);
    const hit = /"(swagger|openapi)"\s*:/i.test(body) || /swagger-ui/i.test(body) || /"activeProfiles"|"propertySources"/i.test(body);
    if (hit) {
      findings.push({
        category: "api", severity: p.startsWith("/actuator") ? "high" : "medium",
        owasp: "A05:2021 Security Misconfiguration",
        title: `Internal API surface exposed at ${p}`,
        description: p.startsWith("/actuator")
          ? "A Spring Boot Actuator endpoint is publicly readable. These endpoints leak environment variables, config, and sometimes credentials, and some allow shutdown or heap dumps."
          : "Machine-readable API documentation is public. It hands attackers a complete map of every endpoint, parameter and auth scheme to target.",
        recommendation: p.startsWith("/actuator")
          ? "Restrict actuator endpoints to an internal network and set management.endpoints.web.exposure.include=health."
          : "Require authentication for API docs, or publish them only on an internal/partner portal.",
        evidence: `GET ${base + p}\nStatus: 200\nBody snippet:\n${body}`,
      });
    }
  }

  // ---- GraphQL introspection ----
  const gqlPaths = ["/graphql", "/api/graphql"];
  for (const p of gqlPaths) {
    const r = await safeFetch(base + p, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "SentraX-Scanner/2.0" },
      body: JSON.stringify({ query: "{__schema{queryType{name}}}" }),
    });
    if (!r) continue;
    note(p, r.status, "graphql introspection");
    const body = (await r.text().catch(() => "")).slice(0, 400);
    if (r.status === 200 && /__schema|queryType/i.test(body)) {
      findings.push({
        category: "api", severity: "high", owasp: "A05:2021 Security Misconfiguration",
        title: `GraphQL introspection enabled at ${p}`,
        description: "The GraphQL schema can be downloaded by anyone, revealing every type, field, mutation and hidden admin operation — the standard first step in a GraphQL attack.",
        recommendation: "Disable introspection in production, enforce query depth/complexity limits, and require authentication on the endpoint.",
        evidence: `POST ${base + p}\nQuery: {__schema{queryType{name}}}\nStatus: 200\nResponse:\n${body}`,
      });
      break;
    }
  }

  // ---- WordPress-specific surface ----
  const isWp = tech.some((t) => /wordpress/i.test(t.name)) || /wp-content|wp-includes/i.test(html);
  if (isWp) {
    const users = await safeFetch(base + "/wp-json/wp/v2/users");
    if (users) {
      note("/wp-json/wp/v2/users", users.status);
      const body = (await users.text().catch(() => "")).slice(0, 400);
      if (users.status === 200 && /"slug"\s*:/.test(body)) {
        findings.push({
          category: "cms", severity: "medium", owasp: "A01:2021 Broken Access Control",
          title: "WordPress user enumeration via REST API",
          description: "The /wp-json/wp/v2/users endpoint lists valid usernames. Attackers use these directly in password-spraying and phishing campaigns.",
          recommendation: "Restrict the users endpoint (security plugin or a rest_endpoints filter), and enforce MFA plus login rate-limiting.",
          evidence: `GET ${base}/wp-json/wp/v2/users\nStatus: 200\n${body}`,
        });
      }
    }
    const xmlrpc = await safeFetch(base + "/xmlrpc.php", { method: "POST", body: "<methodCall><methodName>system.listMethods</methodName></methodCall>" });
    if (xmlrpc) {
      note("/xmlrpc.php", xmlrpc.status);
      const body = (await xmlrpc.text().catch(() => "")).slice(0, 300);
      if (xmlrpc.status === 200 && /methodResponse|params/i.test(body)) {
        findings.push({
          category: "cms", severity: "medium", owasp: "A07:2021 Identification & Auth Failures",
          title: "WordPress XML-RPC endpoint is enabled",
          description: "xmlrpc.php allows hundreds of login attempts in a single request (system.multicall) and can be abused for pingback-based DDoS reflection.",
          recommendation: "Block /xmlrpc.php at the web server or CDN unless a legacy integration requires it.",
          evidence: `POST ${base}/xmlrpc.php\nStatus: 200\n${body}`,
        });
      }
    }
    const readme = await safeFetch(base + "/readme.html");
    if (readme && readme.status === 200) {
      const body = (await readme.text().catch(() => "")).slice(0, 500);
      const ver = /version\s+([\d.]+)/i.exec(body)?.[1];
      note("/readme.html", 200, ver);
      if (ver) findings.push({
        category: "cms", severity: "low", owasp: "A06:2021 Vulnerable & Outdated Components",
        title: `WordPress version disclosed (${ver})`,
        description: "The default readme.html reveals the exact core version, letting attackers match it against public exploit databases.",
        recommendation: "Delete readme.html and license.txt after deployment and remove the generator meta tag.",
        evidence: `GET ${base}/readme.html\nDetected version: ${ver}`,
      });
    }
  }

  // ---- Verbose error handling ----
  const errProbe = await safeFetch(`${base}/sentrax-nonexistent-${Date.now().toString(36)}`);
  if (errProbe) {
    note("/<random-404>", errProbe.status);
    const body = (await errProbe.text().catch(() => "")).slice(0, 4000);
    const stack = /stack trace|at [\w.$]+\([^)]*\.(java|php|py|rb|js):\d+|Traceback \(most recent call last\)|Exception in thread|Whitelabel Error Page|Fatal error:|Warning: include\(|\.cfm|System\.Web\.HttpException/i.exec(body);
    if (stack) {
      findings.push({
        category: "exposure", severity: "medium", owasp: "A05:2021 Security Misconfiguration",
        title: "Verbose error page leaks server internals",
        description: "An unhandled request returned a debug/stack-trace page. These disclose file paths, framework versions and sometimes SQL or credentials, accelerating exploitation.",
        recommendation: "Disable debug mode in production and return a generic error page while logging details server-side.",
        evidence: `GET ${base}/sentrax-nonexistent-…\nStatus: ${errProbe.status}\nMatched: ${stack[0]}\n\n${body.slice(0, 500)}`,
      });
    }
  }

  // ---- Dangerous HTTP methods (OPTIONS) ----
  const opt = await safeFetch(base + "/", { method: "OPTIONS" });
  if (opt) {
    const allow = opt.headers.get("allow") || opt.headers.get("access-control-allow-methods") || "";
    note("OPTIONS /", opt.status, allow);
    const risky = ["PUT", "DELETE", "PATCH", "CONNECT"].filter((m) => new RegExp(`\\b${m}\\b`, "i").test(allow));
    if (risky.length) {
      findings.push({
        category: "infra", severity: "medium", owasp: "A05:2021 Security Misconfiguration",
        title: `Write HTTP methods advertised: ${risky.join(", ")}`,
        description: "The server advertises state-changing HTTP methods on the document root. If access control is weak, attackers may upload or delete content directly.",
        recommendation: "Restrict allowed methods to GET/HEAD/POST at the web server or WAF, and verify authorization on any method you keep.",
        evidence: `OPTIONS ${base}/\nStatus: ${opt.status}\nAllow: ${allow}`,
      });
    }
  }

  // ---- Cache-poisoning / host-header reflection ----
  const poison = await safeFetch(base + "/", { headers: { "user-agent": "SentraX-Scanner/2.0", "x-forwarded-host": "sentrax-canary.example" } });
  if (poison) {
    const body = (await poison.text().catch(() => "")).slice(0, 200_000);
    const loc = poison.headers.get("location") || "";
    if (body.includes("sentrax-canary.example") || loc.includes("sentrax-canary.example")) {
      findings.push({
        category: "infra", severity: "high", owasp: "A05:2021 Security Misconfiguration",
        title: "X-Forwarded-Host is reflected into the response",
        description: "The application builds absolute URLs from an attacker-controllable header. Combined with a shared cache this yields web-cache poisoning, and on password-reset flows it yields account takeover via poisoned reset links.",
        recommendation: "Ignore X-Forwarded-Host / Host from untrusted sources, use a configured canonical base URL, and validate the Host against an allow-list at the edge.",
        evidence: `GET ${base}/  with  X-Forwarded-Host: sentrax-canary.example\nReflected in: ${loc.includes("sentrax-canary.example") ? "Location header" : "response body"}\nLocation: ${loc || "(none)"}`,
      });
    }
  }

  // ---- robots.txt intelligence ----
  const robots = await safeFetch(base + "/robots.txt");
  if (robots && robots.status === 200) {
    const body = (await robots.text().catch(() => "")).slice(0, 5000);
    note("/robots.txt", 200);
    const juicy = body.split("\n")
      .map((l) => l.trim())
      .filter((l) => /^disallow:/i.test(l) && /admin|backup|private|internal|config|db|sql|staging|test|secret|\.git|api/i.test(l));
    if (juicy.length) {
      findings.push({
        category: "exposure", severity: "low", owasp: "A01:2021 Broken Access Control",
        title: `robots.txt advertises ${juicy.length} sensitive path(s)`,
        description: "Disallow rules are a public list of the paths you consider sensitive. Attackers read robots.txt first precisely to find admin and backup locations.",
        recommendation: "Do not name sensitive paths in robots.txt; protect them with authentication and use noindex headers instead.",
        evidence: juicy.slice(0, 12).map((l) => "  " + l).join("\n"),
      });
    }
  }

  return { findings, probes };
}

/** Additional DNS / mail-authentication and attack-surface intelligence. */
async function checkDnsDeep(host: string): Promise<Finding[]> {
  const out: Finding[] = [];
  const apex = host.split(".").slice(-2).join(".");
  const [mx, mtaSts, bimi, dkimDefault, spfTxt] = await Promise.all([
    dohQuery(apex, "MX"),
    dohQuery(`_mta-sts.${apex}`, "TXT"),
    dohQuery(`default._bimi.${apex}`, "TXT"),
    dohQuery(`default._domainkey.${apex}`, "TXT"),
    dohQuery(apex, "TXT"),
  ]);

  if (mx.length) {
    if (!mtaSts.some((r) => /v=STSv1/i.test(r))) {
      out.push({
        category: "email", severity: "low", owasp: "A02:2021 Cryptographic Failures",
        title: "No MTA-STS policy for inbound mail",
        description: "Without MTA-STS, a network attacker can strip TLS from mail delivered to your domain and read or alter messages in transit.",
        recommendation: `Publish "_mta-sts.${apex} TXT v=STSv1; id=..." plus a policy file at https://mta-sts.${apex}/.well-known/mta-sts.txt, and add TLS-RPT reporting.`,
        evidence: `TXT _mta-sts.${apex}: ${mtaSts.join(" | ") || "(none)"}\nMX: ${mx.join(", ")}`,
      });
    }
    if (!dkimDefault.some((r) => /v=DKIM1/i.test(r))) {
      out.push({
        category: "email", severity: "low", owasp: "A07:2021 Identification & Auth Failures",
        title: "No DKIM key at the default selector",
        description: "No DKIM record was found at default._domainkey. If your mail is not DKIM-signed, DMARC cannot pass on forwarded mail and your messages are easier to spoof and more likely to land in spam.",
        recommendation: "Enable DKIM signing at your mail provider and publish the selector's public key in DNS (note: a custom selector may already be in use).",
        evidence: `TXT default._domainkey.${apex}: ${dkimDefault.join(" | ") || "(none)"}`,
      });
    }
    if (bimi.length === 0) {
      out.push({
        category: "email", severity: "info",
        title: "No BIMI record (brand indicator) published",
        description: "BIMI displays your verified logo next to authenticated mail in major inboxes. It requires DMARC at enforcement and improves both trust and phishing resistance for your customers.",
        recommendation: "Once DMARC is at p=quarantine or p=reject, publish a BIMI record with an SVG Tiny PS logo (and a VMC for Gmail/Apple).",
        evidence: `TXT default._bimi.${apex}: (none)`,
      });
    }
  }

  const spf = spfTxt.find((r) => /v=spf1/i.test(r));
  if (spf) {
    const lookups = (spf.match(/\b(include|a|mx|ptr|exists|redirect)[:=]/gi) || []).length;
    if (lookups > 10) {
      out.push({
        category: "email", severity: "medium", owasp: "A07:2021 Identification & Auth Failures",
        title: `SPF record exceeds the 10 DNS-lookup limit (${lookups})`,
        description: "SPF evaluation fails with a permerror above 10 lookups, so receivers ignore the policy entirely and your legitimate mail can be spoofed or rejected.",
        recommendation: "Flatten or consolidate include: mechanisms, or use an SPF-macro/flattening service to stay under 10 lookups.",
        evidence: `SPF: ${spf}\nMechanism lookups counted: ${lookups}`,
      });
    }
    if (/\bptr[:\s]/i.test(spf)) {
      out.push({
        category: "email", severity: "low",
        title: "SPF uses the deprecated ptr mechanism",
        description: "The ptr mechanism is deprecated by RFC 7208, is slow, and many receivers ignore or fail it.",
        recommendation: "Remove ptr and list sending hosts with ip4/ip6/include mechanisms.",
        evidence: `SPF: ${spf}`,
      });
    }
  }

  // Certificate-transparency attack surface
  try {
    const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(apex)}&output=json`, {
      headers: { accept: "application/json", "user-agent": "SentraX-Scanner/2.0" },
      signal: AbortSignal.timeout(9000),
    });
    if (r.ok) {
      const rows = await r.json() as { name_value?: string }[];
      const names = new Set<string>();
      for (const row of rows.slice(0, 3000)) {
        for (const n of (row.name_value ?? "").split("\n")) {
          const clean = n.trim().toLowerCase();
          if (clean && !clean.startsWith("*.") && clean.endsWith(apex)) names.add(clean);
        }
      }
      const risky = Array.from(names).filter((n) => /dev|test|staging|stage|uat|admin|internal|vpn|beta|old|backup|jenkins|git|mail|api/i.test(n));
      if (names.size > 0) {
        out.push({
          category: "dns", severity: risky.length ? "medium" : "info",
          owasp: "A05:2021 Security Misconfiguration",
          title: `${names.size} subdomain(s) discovered in certificate transparency${risky.length ? ` — ${risky.length} look non-production` : ""}`,
          description: risky.length
            ? "Certificate transparency logs reveal hostnames such as staging, dev, admin or VPN endpoints. Non-production hosts typically have weaker controls and are a common initial foothold."
            : "Certificate transparency logs reveal the public hostname inventory for this domain. This is your attack surface as an attacker enumerates it.",
          recommendation: "Inventory every hostname, take unused ones out of DNS, put non-production environments behind SSO/VPN or IP allow-listing, and monitor CT logs for unexpected certificates.",
          evidence: `crt.sh query: %.${apex}\nTotal unique hostnames: ${names.size}\n` +
            (risky.length ? `Non-production / sensitive candidates:\n${risky.slice(0, 25).map((n) => "  • " + n).join("\n")}\n` : "") +
            `Sample:\n${Array.from(names).slice(0, 20).map((n) => "  • " + n).join("\n")}`,
        });
      }
    }
  } catch { /* CT lookup is best-effort */ }

  return out;
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

  // Step 5: OWASP active probes + DNS/email + deep surface analysis
  let probes: { path: string; status: number; note?: string }[] = [];
  findings.push(...analyzePolicyQuality(h, finalUrl));
  findings.push(...analyzeCookieQuality(cookies));
  findings.push(...analyzeLibraries(html));
  findings.push(...analyzeFormsAndPrivacy(html, url));
  try {
    const [owasp, dnsFindings, deepDns, deep] = await Promise.all([
      checkOwaspProbes(rawUrl, url, html),
      checkDnsAndEmail(url.hostname),
      checkDnsDeep(url.hostname),
      checkDeepSurface(url, html, tech),
    ]);
    findings.push(...owasp.findings, ...dnsFindings, ...deepDns, ...deep.findings);
    probes = [...owasp.probes, ...deep.probes];
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
