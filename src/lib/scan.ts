// Demo security-assessment generator. This is intentionally isolated so it can
// be swapped for real integrations later (OWASP ZAP, Nmap, threat intel, AI).

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type RiskLevel = "Low" | "Medium" | "High";

export interface DemoFinding {
  title: string;
  severity: Severity;
  description: string;
  recommendation: string;
}

const FINDING_POOL: DemoFinding[] = [
  {
    title: "Missing Content-Security-Policy header",
    severity: "high",
    description:
      "The site does not send a Content-Security-Policy header, which helps mitigate XSS and data-injection attacks by controlling which resources the browser may load.",
    recommendation:
      "Define a strict CSP that only allows trusted sources for scripts, styles, and frames.",
  },
  {
    title: "Missing Strict-Transport-Security (HSTS) header",
    severity: "medium",
    description:
      "Without HSTS, browsers may attempt an unencrypted HTTP connection before upgrading to HTTPS, exposing users to downgrade attacks.",
    recommendation:
      "Set 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' on all HTTPS responses.",
  },
  {
    title: "Missing X-Frame-Options / frame-ancestors",
    severity: "medium",
    description:
      "The application can be embedded in an iframe, enabling potential clickjacking attacks.",
    recommendation:
      "Set 'X-Frame-Options: DENY' or use CSP 'frame-ancestors none'.",
  },
  {
    title: "TLS certificate expiring soon",
    severity: "low",
    description:
      "The certificate is valid but will expire within 45 days, risking service disruption.",
    recommendation:
      "Automate renewal (e.g. via ACME/Let's Encrypt) and add monitoring alerts.",
  },
  {
    title: "Outdated JavaScript framework detected",
    severity: "high",
    description:
      "An older library version with known CVEs is loaded in production.",
    recommendation:
      "Upgrade to the latest supported release and enable automated dependency scanning.",
  },
  {
    title: "Weak cipher suites enabled",
    severity: "medium",
    description:
      "Server negotiates TLS ciphers that are considered weak by current NIST guidance.",
    recommendation:
      "Disable TLS 1.0/1.1 and enforce modern AEAD ciphers (TLS_AES_128_GCM_SHA256, etc.).",
  },
  {
    title: "Server version exposed via banner",
    severity: "low",
    description:
      "HTTP responses reveal precise server software and version, aiding attacker reconnaissance.",
    recommendation:
      "Remove or obfuscate the 'Server' response header at the edge or web server.",
  },
  {
    title: "Cookies missing Secure/HttpOnly flags",
    severity: "high",
    description:
      "Session cookies are set without the Secure and HttpOnly attributes, exposing them to interception and script access.",
    recommendation:
      "Set Secure, HttpOnly, and SameSite=Lax (or Strict) on all authentication cookies.",
  },
  {
    title: "Open redirect on login callback",
    severity: "medium",
    description:
      "The /callback endpoint accepts arbitrary 'next' parameters, enabling phishing redirection.",
    recommendation:
      "Allow only same-origin relative paths in redirect parameters.",
  },
  {
    title: "No rate limiting on authentication endpoint",
    severity: "high",
    description:
      "Login and password reset endpoints allow unlimited requests, enabling credential stuffing.",
    recommendation:
      "Add IP + account-based rate limits and CAPTCHA challenges after repeated failures.",
  },
];

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 22,
  high: 14,
  medium: 8,
  low: 4,
  info: 1,
};

export function generateDemoAssessment(website: string): {
  score: number;
  risk: RiskLevel;
  findings: DemoFinding[];
} {
  // Deterministic-ish selection so the same URL keeps the same result.
  const seed = Array.from(website).reduce((a, c) => a + c.charCodeAt(0), 0);
  const picks = 4 + (seed % 4); // 4-7 findings
  const findings: DemoFinding[] = [];
  const pool = [...FINDING_POOL];
  for (let i = 0; i < picks; i++) {
    const idx = (seed + i * 7) % pool.length;
    findings.push(pool.splice(idx % pool.length, 1)[0]);
  }
  const penalty = findings.reduce((a, f) => a + SEVERITY_WEIGHT[f.severity], 0);
  const score = Math.max(15, Math.min(98, 100 - penalty));
  const risk: RiskLevel = score >= 80 ? "Low" : score >= 55 ? "Medium" : "High";
  return { score, risk, findings };
}

export const SCAN_STEPS = [
  { key: "website", label: "Website Analysis", detail: "Fetching DNS and HTTP fingerprint" },
  { key: "ssl", label: "SSL/TLS Check", detail: "Validating certificate chain & ciphers" },
  { key: "headers", label: "Security Headers", detail: "Inspecting CSP, HSTS, X-Frame-Options" },
  { key: "tech", label: "Technology Detection", detail: "Identifying frameworks & versions" },
  { key: "risk", label: "Risk Evaluation", detail: "Correlating findings & scoring risk" },
] as const;
