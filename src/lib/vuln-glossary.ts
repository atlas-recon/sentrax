// In-app knowledge base explaining common vulnerability categories.
// Used on the dashboard "Vulnerability Explainer" panel and in reports.

export interface VulnDoc {
  slug: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  owasp: string;
  what: string;      // What the issue is
  how: string;       // How an attacker exploits it
  impact: string;    // Real-world impact
  fix: string;       // How to fix
  matches: RegExp;   // Regex to match finding titles to this doc
}

export const VULN_DOCS: VulnDoc[] = [
  {
    slug: "sql-injection",
    title: "SQL Injection",
    severity: "critical",
    owasp: "A03:2021 Injection",
    what: "The application builds SQL queries by concatenating user input, so tampering with input changes the query itself.",
    how: "An attacker sends a payload like `1' OR '1'='1` or `1; DROP TABLE users;--` in a URL parameter, form field, or header. If the DB errors leak or the response changes, the attacker refines the payload to extract or modify data.",
    impact: "Full database read (customer PII, password hashes, payment info), data destruction, authentication bypass, and in some stacks remote code execution on the DB host.",
    fix: "Use parameterized queries / prepared statements (`?` or `$1` placeholders). Never string-concatenate SQL. Add a WAF rule as defense in depth. Suppress verbose DB errors in production.",
    matches: /sql|injection.*database|db error/i,
  },
  {
    slug: "xss",
    title: "Cross-Site Scripting (XSS)",
    severity: "high",
    owasp: "A03:2021 Injection",
    what: "User-controlled input is rendered back into HTML without encoding, letting attackers execute JavaScript in a victim's browser.",
    how: "The attacker crafts a link containing `<script>...</script>` or `<svg onload=...>`. When a victim opens it, their browser runs the attacker's script in the site's origin.",
    impact: "Session hijacking (cookie theft), account takeover, keystroke logging, phishing overlays, and pivot to internal admin panels.",
    fix: "HTML-encode all user input on output. Use frameworks that auto-escape (React, Vue, Django templates). Enforce a strict Content-Security-Policy that blocks inline scripts.",
    matches: /xss|cross.?site scripting|reflected input/i,
  },
  {
    slug: "missing-headers",
    title: "Missing Security Headers",
    severity: "medium",
    owasp: "A05:2021 Security Misconfiguration",
    what: "HTTP response headers like CSP, HSTS, X-Frame-Options, and X-Content-Type-Options tell the browser how to protect the page. Missing them removes defense-in-depth.",
    how: "Without HSTS, an attacker on the same Wi-Fi can downgrade HTTPS to HTTP. Without X-Frame-Options, the site can be silently framed for clickjacking. Without CSP, any injected script executes freely.",
    impact: "Turns minor bugs into full exploits: an XSS becomes a session-stealer, a session hijack survives across networks, a UI element becomes a clickjacked confirm button.",
    fix: "Set `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`, `Content-Security-Policy` (strict), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`.",
    matches: /header|csp|hsts|x-frame|x-content-type|referrer.policy|permissions.policy/i,
  },
  {
    slug: "insecure-cookies",
    title: "Insecure Cookies",
    severity: "high",
    owasp: "A02:2021 Cryptographic Failures",
    what: "Session/auth cookies are set without the `Secure`, `HttpOnly`, or `SameSite` flags.",
    how: "Without `Secure`, cookies leak on the first HTTP request. Without `HttpOnly`, any XSS bug can read them via `document.cookie`. Without `SameSite`, they ride along in cross-site requests, enabling CSRF.",
    impact: "Full account takeover with a single stolen cookie — no password needed. Persistent access until the session expires.",
    fix: "Set every session/auth cookie with `Secure; HttpOnly; SameSite=Lax` (or `Strict`). Rotate the cookie on login and privilege changes.",
    matches: /cookie/i,
  },
  {
    slug: "exposed-files",
    title: "Sensitive File Exposure",
    severity: "critical",
    owasp: "A01:2021 Broken Access Control",
    what: "Files like `.env`, `.git/`, `backup.sql`, `phpinfo.php`, or `composer.json` are reachable from the public internet.",
    how: "The attacker requests common paths directly. Automated scanners (masscan + web probes) do this within seconds of a domain being registered.",
    impact: "Leaked API keys, database credentials, source code, customer backups. Often the single fastest path from zero to full breach.",
    fix: "Block access to dotfiles, `.git`, `.env`, backups, and dev endpoints at the web server or CDN. Never deploy them in the artifact in the first place.",
    matches: /exposed|\.env|\.git|backup|phpinfo|directory listing/i,
  },
  {
    slug: "open-redirect",
    title: "Open Redirect",
    severity: "high",
    owasp: "A01:2021 Broken Access Control",
    what: "An endpoint takes a URL in a parameter (`?next=`, `?url=`) and redirects to it without validating the target.",
    how: "The attacker sends a link like `https://your-site.com/login?next=https://evil.example` — victims trust your domain and land on the phishing page. Also used to steal OAuth codes.",
    impact: "Phishing with a legitimate domain, OAuth token/code theft, and reputation damage. Search engines and email filters trust the redirect source.",
    fix: "Validate redirect targets against a strict allowlist of internal paths. Reject any absolute URL to an external host.",
    matches: /open redirect|redirect/i,
  },
  {
    slug: "cors",
    title: "CORS Misconfiguration",
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    what: "The server responds with permissive CORS headers (`Access-Control-Allow-Origin: *` with credentials, or reflects arbitrary origins).",
    how: "An attacker's site issues authenticated fetch() to your API. The browser lets the response through because the CORS headers permit it, so the attacker's JS reads private data.",
    impact: "Cross-origin theft of API responses containing user data, session-scoped actions triggered from any site, and bypass of the same-origin protection browsers normally enforce.",
    fix: "Echo only trusted origins in `Access-Control-Allow-Origin`. Never combine `*` with `Access-Control-Allow-Credentials: true`. Prefer a hard-coded allowlist.",
    matches: /cors/i,
  },
  {
    slug: "mixed-content",
    title: "Mixed Content",
    severity: "medium",
    owasp: "A02:2021 Cryptographic Failures",
    what: "An HTTPS page loads scripts, iframes, or images over plain HTTP.",
    how: "A network attacker (public Wi-Fi, ISP) intercepts the HTTP asset and swaps it for a malicious one. Because it loads in the HTTPS page's context, it runs with full privileges.",
    impact: "Script injection into a 'secure' page, defacement, credential theft — all while the browser still shows the padlock.",
    fix: "Rewrite all asset URLs to `https://` or protocol-relative `//`. Add `Content-Security-Policy: upgrade-insecure-requests`.",
    matches: /mixed content/i,
  },
  {
    slug: "no-https",
    title: "No HTTPS / Weak TLS",
    severity: "high",
    owasp: "A02:2021 Cryptographic Failures",
    what: "Traffic is served over plain HTTP, or HTTP is not force-redirected to HTTPS.",
    how: "Anyone on the network path (café Wi-Fi, corporate proxy, ISP) reads and modifies traffic. Login credentials and session cookies are visible in cleartext.",
    impact: "Total loss of confidentiality and integrity: credential capture, session theft, injected malware.",
    fix: "Obtain a TLS certificate (Let's Encrypt is free). Force a 301 redirect from HTTP → HTTPS. Enable HSTS with a long max-age.",
    matches: /https|tls|ssl|http.*redirect/i,
  },
  {
    slug: "info-disclosure",
    title: "Information Disclosure",
    severity: "low",
    owasp: "A05:2021 Security Misconfiguration",
    what: "`Server`, `X-Powered-By`, or generator meta tags reveal exact software versions.",
    how: "Attackers use version banners to look up published CVEs and pick a matching exploit — no scanning needed.",
    impact: "Cuts attacker reconnaissance time from hours to seconds and enables targeted exploitation of unpatched versions.",
    fix: "Suppress or generalize the `Server` header at the reverse proxy. Remove `X-Powered-By`. Strip generator meta tags in production builds.",
    matches: /disclosed|server version|x-powered-by/i,
  },
  {
    slug: "dns-email",
    title: "DNS / Email Authentication Missing",
    severity: "medium",
    owasp: "A07:2021 Identification & Auth Failures",
    what: "The domain is missing SPF, DKIM, DMARC, CAA, or DNSSEC records.",
    how: "Without SPF/DKIM/DMARC, attackers can send spoofed email that appears to come from your domain — the classic CEO-fraud / invoice-fraud vector. Without CAA, any CA can issue certificates for your domain.",
    impact: "Business email compromise, brand damage, and unauthorized TLS certificate issuance leading to man-in-the-middle attacks.",
    fix: "Publish SPF (`v=spf1 include:_spf.google.com -all`), a DKIM key, and DMARC (`v=DMARC1; p=reject; rua=mailto:...`). Add a CAA record pinning your CA. Enable DNSSEC at the registrar.",
    matches: /spf|dkim|dmarc|caa|dnssec|dns/i,
  },
  {
    slug: "clickjacking",
    title: "Clickjacking",
    severity: "medium",
    owasp: "A05:2021 Security Misconfiguration",
    what: "The site can be embedded in a hidden `<iframe>` on an attacker's page, letting them trick users into clicking things they can't see.",
    how: "Attacker overlays your app in a transparent iframe under a fake UI. Victim thinks they're clicking 'Play video' but actually clicks 'Transfer funds'.",
    impact: "Unauthorized actions performed with the victim's session: transfers, follows, deletes, privilege grants.",
    fix: "Set `Content-Security-Policy: frame-ancestors 'none'` or `X-Frame-Options: DENY` on every response.",
    matches: /clickjack|frame.ancestors|x-frame/i,
  },
];

export function matchDocs(findingTitles: string[]): { doc: VulnDoc; count: number }[] {
  const counts = new Map<string, number>();
  for (const t of findingTitles) {
    for (const d of VULN_DOCS) {
      if (d.matches.test(t)) counts.set(d.slug, (counts.get(d.slug) ?? 0) + 1);
    }
  }
  return VULN_DOCS
    .map((doc) => ({ doc, count: counts.get(doc.slug) ?? 0 }))
    .filter((x) => x.count > 0)
    .sort((a, b) => b.count - a.count);
}
