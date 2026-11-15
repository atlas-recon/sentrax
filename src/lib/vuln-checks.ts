// Additional active vulnerability checks (server-side only usage).
import type { Finding } from "./scan.functions";

const UA = { "user-agent": "ShahinSecurity-Scanner/3.0" };

async function get(url: string, init: RequestInit = {}): Promise<{ status: number; body: string; headers: Headers } | null> {
  try {
    const r = await fetch(url, { redirect: "manual", ...init, headers: { ...UA, ...(init.headers ?? {}) }, signal: AbortSignal.timeout(7000) });
    const body = (await r.text()).slice(0, 60000);
    return { status: r.status, body, headers: r.headers };
  } catch { return null; }
}

const EOL_VERSIONS: { re: RegExp; name: string; minOk: number[] }[] = [
  { re: /PHP\/(\d+)\.(\d+)(?:\.(\d+))?/i, name: "PHP", minOk: [8, 1] },
  { re: /Apache\/(\d+)\.(\d+)\.(\d+)/i, name: "Apache httpd", minOk: [2, 4, 58] },
  { re: /nginx\/(\d+)\.(\d+)\.(\d+)/i, name: "nginx", minOk: [1, 24, 0] },
  { re: /Microsoft-IIS\/(\d+)\.(\d+)/i, name: "Microsoft IIS", minOk: [10, 0] },
  { re: /OpenSSL\/(\d+)\.(\d+)\.(\d+)/i, name: "OpenSSL", minOk: [3, 0, 0] },
];

function older(v: number[], min: number[]) {
  for (let i = 0; i < min.length; i++) { const a = v[i] ?? 0; if (a !== min[i]) return a < min[i]; }
  return false;
}

export async function checkActualVulnerabilities(url: URL, html: string, headers: Headers): Promise<{ findings: Finding[]; probes: { path: string; status: number; note?: string }[] }> {
  const findings: Finding[] = [];
  const probes: { path: string; status: number; note?: string }[] = [];
  const base = url.origin;

  // 1. Outdated / end-of-life server software from banners
  const banner = [headers.get("server"), headers.get("x-powered-by"), headers.get("x-aspnet-version") && `ASP.NET/${headers.get("x-aspnet-version")}`].filter(Boolean).join(" ");
  for (const s of EOL_VERSIONS) {
    const m = banner.match(s.re);
    if (!m) continue;
    const v = m.slice(1).filter(Boolean).map(Number);
    if (older(v, s.minOk)) {
      findings.push({
        category: "infra", severity: "high", owasp: "A06:2021 Vulnerable and Outdated Components",
        title: `Outdated ${s.name} ${v.join(".")} detected`,
        description: `The server announces ${s.name} ${v.join(".")}, which is below the supported baseline (${s.minOk.join(".")}). Older releases carry publicly known CVEs that attackers exploit with ready-made tools.`,
        recommendation: `Upgrade ${s.name} to a currently supported release and hide version numbers from response headers.`,
        evidence: `Response banner: ${banner}`,
      });
    }
  }

  // 2. Extra sensitive files & directory listing
  const files: { p: string; test: RegExp; sev: Finding["severity"]; what: string }[] = [
    { p: "/.DS_Store", test: /Bud1/, sev: "medium", what: "macOS folder index (reveals file names)" },
    { p: "/.svn/entries", test: /^\d+\s|dir/m, sev: "high", what: "Subversion metadata (source code exposure)" },
    { p: "/.htaccess", test: /RewriteRule|Deny from|AuthType/i, sev: "medium", what: "Apache configuration" },
    { p: "/web.config", test: /<configuration/i, sev: "high", what: "IIS configuration (may contain secrets)" },
    { p: "/composer.json", test: /"require"/, sev: "low", what: "PHP dependency manifest" },
    { p: "/package.json", test: /"dependencies"|"name"\s*:/, sev: "low", what: "Node dependency manifest" },
    { p: "/docker-compose.yml", test: /services:/, sev: "high", what: "Docker infrastructure definition" },
    { p: "/.env.backup", test: /=[^\n]/, sev: "critical", what: "Backup of environment secrets" },
    { p: "/.env.local", test: /=[^\n]/, sev: "critical", what: "Local environment secrets" },
    { p: "/dump.sql", test: /insert into|create table/i, sev: "critical", what: "Database dump" },
    { p: "/database.sql", test: /insert into|create table/i, sev: "critical", what: "Database dump" },
    { p: "/wp-config.php~", test: /DB_PASSWORD/, sev: "critical", what: "WordPress config backup with DB password" },
    { p: "/id_rsa", test: /PRIVATE KEY/, sev: "critical", what: "SSH private key" },
    { p: "/.aws/credentials", test: /aws_access_key_id/i, sev: "critical", what: "AWS credentials" },
    { p: "/error_log", test: /PHP (Warning|Fatal|Notice)/, sev: "medium", what: "Server error log" },
  ];
  const dirs = ["/uploads/", "/images/", "/files/", "/backup/", "/assets/", "/wp-content/uploads/"];
  const results = await Promise.all([
    ...files.map(async (f) => ({ kind: "file" as const, f, r: await get(base + f.p) })),
    ...dirs.map(async (d) => ({ kind: "dir" as const, d, r: await get(base + d) })),
  ]);
  for (const res of results) {
    if (res.kind === "file") {
      const { f, r } = res;
      if (!r) continue;
      probes.push({ path: f.p, status: r.status });
      if (r.status === 200 && f.test.test(r.body) && !/<html/i.test(r.body.slice(0, 200))) {
        findings.push({
          category: "exposure", severity: f.sev, owasp: "A05:2021 Security Misconfiguration",
          title: `Exposed sensitive file: ${f.p}`,
          description: `${f.what} is publicly downloadable. Anyone can read it without logging in.`,
          recommendation: `Remove ${f.p} from the web root immediately, block it at the server, and rotate any secrets it contained.`,
          evidence: `GET ${base}${f.p} → ${r.status}\n\n${r.body.slice(0, 300)}`,
        });
      }
    } else {
      const { d, r } = res;
      if (!r) continue;
      probes.push({ path: d, status: r.status });
      if (r.status === 200 && /<title>\s*Index of|Directory listing for|\[To Parent Directory\]/i.test(r.body)) {
        findings.push({
          category: "exposure", severity: "medium", owasp: "A01:2021 Broken Access Control",
          title: `Directory listing enabled: ${d}`,
          description: "The server shows a full list of files in this folder, letting attackers browse uploads, backups and internal documents.",
          recommendation: "Disable auto-indexing (Apache: Options -Indexes, nginx: autoindex off) and add an index file.",
          evidence: `GET ${base}${d} → 200\n${r.body.match(/<title>[^<]*<\/title>/i)?.[0] ?? ""}`,
        });
      }
    }
  }

  // 3. Parameter-based injection tests (links with query strings on the page + the target itself)
  const params = new Set<string>();
  for (const m of html.matchAll(/href=["']([^"']+\?[^"'#]+)["']/gi)) {
    try { const u = new URL(m[1].replace(/&amp;/g, "&"), base); if (u.origin === base) params.add(u.toString()); } catch { /* ignore */ }
    if (params.size >= 4) break;
  }
  if (url.search) params.add(url.toString());
  for (const target of params) {
    const u = new URL(target);
    const key = Array.from(u.searchParams.keys())[0];
    if (!key) continue;
    const orig = u.searchParams.get(key) ?? "";

    // Boolean-based blind SQLi
    const mk = (v: string) => { const x = new URL(u); x.searchParams.set(key, v); return x.toString(); };
    const [t, f, o] = await Promise.all([get(mk(`${orig}' AND '1'='1`)), get(mk(`${orig}' AND '1'='2`)), get(mk(orig))]);
    if (t && f && o && o.status === 200 && t.status === 200) {
      const lenDiff = Math.abs(t.body.length - f.body.length);
      const tSame = Math.abs(t.body.length - o.body.length) < 50;
      if (tSame && lenDiff > 200) {
        findings.push({
          category: "injection", severity: "critical", owasp: "A03:2021 Injection",
          title: `Possible blind SQL injection in parameter "${key}"`,
          description: "The page responds differently to a TRUE vs FALSE SQL condition, which indicates user input is placed directly into a database query. Attackers can extract the entire database this way.",
          recommendation: "Use parameterised queries / prepared statements for every database call and validate input types. Verify manually with an authorised penetration test.",
          evidence: `Parameter: ${key}\nTRUE payload length: ${t.body.length}\nFALSE payload length: ${f.body.length}\nOriginal length: ${o.body.length}\nURL: ${u.pathname}`,
        });
      }
    }

    // Path traversal / LFI
    const lfi = await get(mk("../../../../../../etc/passwd"));
    if (lfi && /root:.*:0:0:/.test(lfi.body)) {
      findings.push({
        category: "injection", severity: "critical", owasp: "A01:2021 Broken Access Control",
        title: `Path traversal / file inclusion in parameter "${key}"`,
        description: "The server returned the contents of /etc/passwd, proving an attacker can read arbitrary server files including configuration and secrets.",
        recommendation: "Never build file paths from user input. Use an allow-list of file names and resolve paths inside a fixed directory.",
        evidence: `GET ${u.pathname}?${key}=../../../../../../etc/passwd\n${lfi.body.match(/root:.*:0:0:[^\n]*/)?.[0]}`,
      });
    }

    // Server-side template injection
    const ssti = await get(mk("{{7*191}}${7*191}"));
    if (ssti && ssti.body.includes("1337") && !(o?.body.includes("1337"))) {
      findings.push({
        category: "injection", severity: "critical", owasp: "A03:2021 Injection",
        title: `Server-side template injection in parameter "${key}"`,
        description: "A math expression sent in the parameter was evaluated by the server (7×191 = 1337). Template injection usually leads to full remote code execution.",
        recommendation: "Never render user input as a template. Pass it as data to the template engine and enable sandboxing.",
        evidence: `Payload: {{7*191}}\${7*191}\nResponse contained: 1337`,
      });
    }
  }

  // 4. Host header injection on password reset style pages / absolute links
  const hh = await get(base + "/", { headers: { host: "shahin-host-canary.example" } as Record<string, string> });
  if (hh && (hh.body.includes("shahin-host-canary.example") || (hh.headers.get("location") ?? "").includes("shahin-host-canary.example"))) {
    findings.push({
      category: "infra", severity: "medium", owasp: "A05:2021 Security Misconfiguration",
      title: "Host header injection",
      description: "The site trusts the Host header and reflects it into links. This can poison password-reset emails and caches.",
      recommendation: "Configure an explicit allow-list of hostnames and build absolute URLs from configuration, not request headers.",
      evidence: "Request Host: shahin-host-canary.example was reflected in the response.",
    });
  }

  // 5. Clickjacking-sensitive login page without framing protection
  const hasFrameProt = /frame-ancestors/i.test(headers.get("content-security-policy") ?? "") || !!headers.get("x-frame-options");
  if (!hasFrameProt && /type=["']password["']/i.test(html)) {
    findings.push({
      category: "auth", severity: "high", owasp: "A04:2021 Insecure Design",
      title: "Login form can be framed (clickjacking on credentials)",
      description: "A password field is shown on a page that any other website can embed invisibly, tricking users into typing credentials or clicking actions.",
      recommendation: "Send 'Content-Security-Policy: frame-ancestors 'none'' (or X-Frame-Options: DENY) on all authenticated and login pages.",
      evidence: `Password field present on ${url.pathname || "/"}; no X-Frame-Options or frame-ancestors.`,
    });
  }

  return { findings, probes };
}
