// Shared client-safe types + UI step metadata for the SentraX scanner.
// Actual scanning runs server-side in `scan.functions.ts`.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type RiskLevel = "Low" | "Medium" | "High";

export const SCAN_STEPS = [
  { key: "website", label: "Website Analysis", detail: "Fetching DNS and HTTP fingerprint" },
  { key: "ssl", label: "SSL/TLS Check", detail: "Validating HTTPS reachability & redirects" },
  { key: "headers", label: "Security Headers", detail: "Inspecting CSP, HSTS, X-Frame-Options" },
  { key: "tech", label: "Technology Detection", detail: "Identifying frameworks & cookies" },
  { key: "risk", label: "Risk Evaluation", detail: "Correlating findings & scoring risk" },
] as const;
