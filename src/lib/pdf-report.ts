import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import logoAsset from "@/assets/shahin-mark.png";

export type PdfSeverity = "critical" | "high" | "medium" | "low" | "info";
export interface PdfFinding {
  title: string;
  severity: PdfSeverity;
  description: string;
  recommendation: string;
  category?: string;
  owasp?: string;
  evidence?: string;
}
export interface PdfReportInput {
  company: string;
  website: string;
  score: number;
  risk: "Low" | "Medium" | "High";
  generatedAt: string;
  summary: string;
  findings: PdfFinding[];
  target?: {
    url?: string;
    finalUrl?: string;
    statusCode?: number;
    protocol?: string;
    hstsRedirect?: boolean;
    server?: string;
    poweredBy?: string;
  };
  tech?: (string | { name: string })[];
}

const BRAND = { primary: [59, 130, 246] as [number, number, number], dark: [15, 23, 42] as [number, number, number], sub: [100, 116, 139] as [number, number, number] };
const SEV_COLOR: Record<PdfSeverity, [number, number, number]> = {
  critical: [153, 27, 27], high: [220, 38, 38], medium: [217, 119, 6], low: [37, 99, 235], info: [100, 116, 139],
};

async function toDataURL(url: string): Promise<string | null> {
  try {
    const res = await fetch(url);
    const blob = await res.blob();
    return await new Promise((resolve) => {
      const r = new FileReader();
      r.onloadend = () => resolve(typeof r.result === "string" ? r.result : null);
      r.readAsDataURL(blob);
    });
  } catch { return null; }
}

function drawHeader(doc: jsPDF, logo: string | null, pageNum: number, totalPages: number) {
  const w = doc.internal.pageSize.getWidth();
  doc.setFillColor(...BRAND.dark);
  doc.rect(0, 0, w, 22, "F");
  if (logo) doc.addImage(logo, "PNG", 12, 4, 14, 14);
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold").setFontSize(13);
  doc.text("Shahin Security", 30, 13);
  doc.setFont("helvetica", "normal").setFontSize(8);
  doc.setTextColor(148, 197, 255);
  doc.text("Security Assessment Report", 30, 18);
  doc.setTextColor(200, 200, 200);
  doc.setFontSize(8);
  doc.text(`Page ${pageNum} of ${totalPages}`, w - 12, 13, { align: "right" });
}

function drawFooter(doc: jsPDF) {
  const w = doc.internal.pageSize.getWidth();
  const h = doc.internal.pageSize.getHeight();
  doc.setDrawColor(220, 220, 220);
  doc.line(12, h - 12, w - 12, h - 12);
  doc.setFont("helvetica", "normal").setFontSize(8).setTextColor(...BRAND.sub);
  doc.text("Confidential — Shahin Security Security Report", 12, h - 6);
  doc.text("shahinsecurity.co.tz", w - 12, h - 6, { align: "right" });
}

function drawScoreDial(doc: jsPDF, x: number, y: number, score: number, risk: string) {
  const r = 22;
  const cx = x + r; const cy = y + r;
  // background ring
  doc.setDrawColor(230, 230, 230).setLineWidth(6);
  doc.circle(cx, cy, r, "S");
  // arc: approximate with many small segments
  const pct = Math.max(0, Math.min(1, score / 100));
  const steps = Math.max(1, Math.round(60 * pct));
  const color: [number, number, number] = risk === "Low" ? [22, 163, 74] : risk === "High" ? [220, 38, 38] : [217, 119, 6];
  doc.setDrawColor(...color).setLineWidth(6);
  const start = -Math.PI / 2;
  for (let i = 0; i < steps; i++) {
    const a1 = start + (i / 60) * Math.PI * 2;
    const a2 = start + ((i + 1) / 60) * Math.PI * 2;
    doc.line(cx + r * Math.cos(a1), cy + r * Math.sin(a1), cx + r * Math.cos(a2), cy + r * Math.sin(a2));
  }
  doc.setFont("helvetica", "bold").setFontSize(20).setTextColor(...BRAND.dark);
  doc.text(String(score), cx, cy + 2, { align: "center" });
  doc.setFont("helvetica", "normal").setFontSize(7).setTextColor(...BRAND.sub);
  doc.text("SCORE / 100", cx, cy + 9, { align: "center" });
}

function drawSeverityBarChart(doc: jsPDF, x: number, y: number, width: number, counts: Record<PdfSeverity, number>) {
  const order: PdfSeverity[] = ["critical", "high", "medium", "low", "info"];
  const max = Math.max(1, ...order.map((k) => counts[k]));
  const barH = 7;
  const gap = 3;
  const labelW = 22;
  const barMaxW = width - labelW - 18;
  order.forEach((sev, i) => {
    const yy = y + i * (barH + gap);
    doc.setFont("helvetica", "bold").setFontSize(8).setTextColor(...BRAND.dark);
    doc.text(sev.toUpperCase(), x, yy + barH - 1.5);
    doc.setFillColor(240, 240, 240);
    doc.rect(x + labelW, yy, barMaxW, barH, "F");
    const w = (counts[sev] / max) * barMaxW;
    doc.setFillColor(...SEV_COLOR[sev]);
    doc.rect(x + labelW, yy, Math.max(0.5, w), barH, "F");
    doc.setFont("helvetica", "normal").setFontSize(9).setTextColor(...BRAND.dark);
    doc.text(String(counts[sev]), x + labelW + barMaxW + 4, yy + barH - 1.5);
  });
}

function drawRiskGauge(doc: jsPDF, x: number, y: number, w: number, score: number) {
  // horizontal segmented bar: 0-54 red, 55-79 amber, 80-100 green
  const segs: [number, number, [number, number, number]][] = [
    [0, 54, [220, 38, 38]], [55, 79, [217, 119, 6]], [80, 100, [22, 163, 74]],
  ];
  const h = 6;
  segs.forEach(([a, b, c]) => {
    const sx = x + (a / 100) * w;
    const sw = ((b - a + 1) / 100) * w;
    doc.setFillColor(...c);
    doc.rect(sx, y, sw, h, "F");
  });
  // marker
  const mx = x + (Math.max(0, Math.min(100, score)) / 100) * w;
  doc.setFillColor(...BRAND.dark);
  doc.triangle(mx - 2.5, y - 1, mx + 2.5, y - 1, mx, y + 2, "F");
  doc.setDrawColor(...BRAND.dark).setLineWidth(0.5);
  doc.line(mx, y, mx, y + h);
  doc.setFont("helvetica", "normal").setFontSize(7).setTextColor(...BRAND.sub);
  doc.text("0", x, y + h + 4); doc.text("55", x + w * 0.55, y + h + 4);
  doc.text("80", x + w * 0.8, y + h + 4); doc.text("100", x + w, y + h + 4, { align: "right" });
}

export async function generateReportPdf(input: PdfReportInput): Promise<Blob> {
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const logo = await toDataURL(logoAsset);
  const pageW = doc.internal.pageSize.getWidth();
  const marginX = 14;
  const contentW = pageW - marginX * 2;

  // === COVER PAGE ===
  doc.setFillColor(...BRAND.dark);
  doc.rect(0, 0, pageW, doc.internal.pageSize.getHeight(), "F");
  if (logo) doc.addImage(logo, "PNG", pageW / 2 - 22, 60, 44, 44);
  doc.setFont("helvetica", "bold").setFontSize(30).setTextColor(255, 255, 255);
  doc.text("Security Assessment", pageW / 2, 125, { align: "center" });
  doc.setFontSize(18).setTextColor(148, 197, 255);
  doc.text("Report", pageW / 2, 137, { align: "center" });
  doc.setDrawColor(...BRAND.primary).setLineWidth(0.8);
  doc.line(pageW / 2 - 30, 145, pageW / 2 + 30, 145);
  doc.setFont("helvetica", "normal").setFontSize(14).setTextColor(255, 255, 255);
  doc.text(input.company, pageW / 2, 160, { align: "center" });
  doc.setFontSize(11).setTextColor(148, 197, 255);
  doc.text(input.website, pageW / 2, 170, { align: "center" });
  doc.setFontSize(10).setTextColor(200, 200, 200);
  doc.text(`Generated: ${input.generatedAt}`, pageW / 2, 240, { align: "center" });
  doc.text("Prepared by Shahin Security  •  Secure. Scan. Protect.", pageW / 2, 250, { align: "center" });

  // === EXECUTIVE SUMMARY ===
  doc.addPage();
  drawHeader(doc, logo, 2, 0);
  doc.setFont("helvetica", "bold").setFontSize(16).setTextColor(...BRAND.dark);
  doc.text("Executive Summary", marginX, 34);
  doc.setDrawColor(...BRAND.primary).setLineWidth(0.6);
  doc.line(marginX, 36.5, marginX + 40, 36.5);

  // score + risk band card
  drawScoreDial(doc, marginX, 44, input.score, input.risk);
  doc.setFont("helvetica", "bold").setFontSize(11).setTextColor(...BRAND.dark);
  doc.text("Overall Risk Level", marginX + 55, 52);
  doc.setFontSize(22).setTextColor(...(input.risk === "Low" ? [22, 163, 74] : input.risk === "High" ? [220, 38, 38] : [217, 119, 6]) as [number, number, number]);
  doc.text(`${input.risk} Risk`, marginX + 55, 63);
  drawRiskGauge(doc, marginX + 55, 72, contentW - 55, input.score);

  doc.setFont("helvetica", "normal").setFontSize(10).setTextColor(...BRAND.dark);
  const summaryLines = doc.splitTextToSize(input.summary, contentW);
  doc.text(summaryLines, marginX, 100);

  // Findings breakdown chart
  const counts: Record<PdfSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  input.findings.forEach((f) => { counts[f.severity]++; });
  doc.setFont("helvetica", "bold").setFontSize(12).setTextColor(...BRAND.dark);
  doc.text("Findings by Severity", marginX, 135);
  drawSeverityBarChart(doc, marginX, 140, contentW, counts);

  // Target details table
  doc.setFont("helvetica", "bold").setFontSize(12).setTextColor(...BRAND.dark);
  doc.text("Target Details", marginX, 195);
  autoTable(doc, {
    startY: 199,
    margin: { left: marginX, right: marginX },
    theme: "grid",
    styles: { fontSize: 9, cellPadding: 2 },
    headStyles: { fillColor: BRAND.dark, textColor: 255 },
    columnStyles: { 0: { fontStyle: "bold", cellWidth: 40 } },
    body: [
      ["Website", input.website],
      ["Requested URL", input.target?.url ?? "—"],
      ["Final URL", input.target?.finalUrl ?? "—"],
      ["Protocol", input.target?.protocol ?? "—"],
      ["HTTP → HTTPS", input.target?.hstsRedirect ? "Redirects" : "No redirect"],
      ["HTTP Status", String(input.target?.statusCode ?? "—")],
      ["Server", input.target?.server ?? "—"],
      ["X-Powered-By", input.target?.poweredBy ?? "—"],
    ],
  });

  // === FINDINGS TABLE (overview) ===
  doc.addPage();
  drawHeader(doc, logo, 3, 0);
  doc.setFont("helvetica", "bold").setFontSize(16).setTextColor(...BRAND.dark);
  doc.text("Findings Overview", marginX, 34);
  doc.setDrawColor(...BRAND.primary).setLineWidth(0.6);
  doc.line(marginX, 36.5, marginX + 40, 36.5);

  const sorted = [...input.findings].sort((a, b) => {
    const rank: Record<PdfSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return rank[a.severity] - rank[b.severity];
  });
  autoTable(doc, {
    startY: 42,
    margin: { left: marginX, right: marginX },
    head: [["#", "Severity", "OWASP", "Finding"]],
    body: sorted.map((f, i) => [String(i + 1), f.severity.toUpperCase(), f.owasp ?? "—", f.title]),
    styles: { fontSize: 9, cellPadding: 2.2 },
    headStyles: { fillColor: BRAND.dark, textColor: 255 },
    columnStyles: {
      0: { cellWidth: 10 }, 1: { cellWidth: 22, fontStyle: "bold" }, 2: { cellWidth: 40 },
    },
    didParseCell: (data) => {
      if (data.section === "body" && data.column.index === 1) {
        const sev = sorted[data.row.index].severity;
        data.cell.styles.textColor = SEV_COLOR[sev];
      }
    },
  });

  // === DETAILED FINDINGS ===
  doc.addPage();
  drawHeader(doc, logo, 4, 0);
  doc.setFont("helvetica", "bold").setFontSize(16).setTextColor(...BRAND.dark);
  doc.text("Detailed Findings & Recommendations", marginX, 34);
  doc.setDrawColor(...BRAND.primary).setLineWidth(0.6);
  doc.line(marginX, 36.5, marginX + 80, 36.5);

  let y = 44;
  const pageH = doc.internal.pageSize.getHeight();
  const ensureSpace = (need: number) => {
    if (y + need > pageH - 18) {
      doc.addPage();
      drawHeader(doc, logo, doc.getNumberOfPages(), 0);
      y = 34;
    }
  };

  sorted.forEach((f, i) => {
    ensureSpace(40);
    // severity ribbon
    doc.setFillColor(...SEV_COLOR[f.severity]);
    doc.rect(marginX, y, 3, 8, "F");
    doc.setFont("helvetica", "bold").setFontSize(11).setTextColor(...BRAND.dark);
    doc.text(`${i + 1}. ${f.title}`, marginX + 6, y + 6);
    y += 10;

    doc.setFont("helvetica", "normal").setFontSize(8).setTextColor(...SEV_COLOR[f.severity]);
    doc.text(`Severity: ${f.severity.toUpperCase()}`, marginX + 6, y);
    if (f.owasp) {
      doc.setTextColor(...BRAND.sub);
      doc.text(`   •   ${f.owasp}`, marginX + 6 + doc.getTextWidth(`Severity: ${f.severity.toUpperCase()}`), y);
    }
    y += 6;

    doc.setFont("helvetica", "bold").setFontSize(9).setTextColor(...BRAND.dark);
    doc.text("Impact", marginX + 6, y); y += 4;
    doc.setFont("helvetica", "normal").setFontSize(9);
    const desc = doc.splitTextToSize(f.description, contentW - 8);
    ensureSpace(desc.length * 4 + 20);
    doc.text(desc, marginX + 6, y); y += desc.length * 4 + 2;

    doc.setFont("helvetica", "bold").setFontSize(9);
    doc.text("Recommendation", marginX + 6, y); y += 4;
    doc.setFont("helvetica", "normal");
    const rec = doc.splitTextToSize(f.recommendation, contentW - 8);
    ensureSpace(rec.length * 4 + 12);
    doc.text(rec, marginX + 6, y); y += rec.length * 4 + 2;

    if (f.evidence) {
      doc.setFont("helvetica", "bold").setFontSize(9);
      doc.text("Evidence", marginX + 6, y); y += 4;
      const ev = doc.splitTextToSize(f.evidence.slice(0, 900), contentW - 10);
      ensureSpace(ev.length * 3.6 + 8);
      doc.setFillColor(245, 247, 250);
      doc.rect(marginX + 6, y - 3, contentW - 6, ev.length * 3.6 + 4, "F");
      doc.setFont("courier", "normal").setFontSize(7.5).setTextColor(...BRAND.dark);
      doc.text(ev, marginX + 8, y);
      y += ev.length * 3.6 + 4;
    }
    y += 6;
    doc.setDrawColor(230, 230, 230);
    doc.line(marginX, y, marginX + contentW, y);
    y += 4;
  });

  // Footer + page numbers on every page
  const total = doc.getNumberOfPages();
  for (let p = 1; p <= total; p++) {
    doc.setPage(p);
    if (p === 1) continue; // cover
    drawFooter(doc);
    // rewrite page number
    doc.setFillColor(...BRAND.dark);
    doc.setTextColor(200, 200, 200).setFontSize(8);
    doc.text(`Page ${p} of ${total}`, pageW - 12, 13, { align: "right" });
  }

  return doc.output("blob");
}
