import { createFileRoute } from "@tanstack/react-router";
import { FileDown } from "lucide-react";
import { toast } from "sonner";

import { PageHeader, PageShell } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { RawBlock } from "@/components/raw-block";
import { FindingValidator } from "@/components/finding-validator";
import { useLatestScan } from "@/hooks/use-scans";
import { buildEngagementSummary, type RiskRating } from "@/lib/engagement";
import { downloadEngagementPdf } from "@/lib/report-pdf";

export const Route = createFileRoute("/report")({
  head: () => ({
    meta: [
      { title: "Engagement Report · NOVAIN Security Lab" },
      { name: "description", content: "Full penetration test engagement report with executive summary, findings, risk ratings, and remediation." },
    ],
  }),
  component: ReportPage,
});

const riskClass: Record<RiskRating, string> = {
  Critical: "border-critical/50 text-critical bg-critical/10",
  High: "border-critical/40 text-critical bg-critical/5",
  Medium: "border-warning/40 text-warning bg-warning/5",
  Low: "border-success/40 text-success bg-success/5",
  Info: "border-border text-muted-foreground",
};

function ReportPage() {
  const { data: scan } = useLatestScan();

  if (!scan) {
    return (
      <PageShell>
        <PageHeader
          eyebrow="Reporting"
          title="Engagement report"
          description="Executive summary, scope, methodology, asset inventory, confirmed findings, risk ratings, and remediation."
          actions={<ScanRunner label="Run scan" />}
        />
        <EmptyScanState context="the engagement report" />
      </PageShell>
    );
  }

  const summary = buildEngagementSummary(scan);

  return (
    <PageShell>
      <PageHeader
        eyebrow="Reporting"
        title="Engagement report"
        description={`${summary.targetHost} · report generated from the latest scan.`}
        actions={
          <>
            <ScanRunner label="Rescan" />
            <Button size="sm" onClick={() => { downloadEngagementPdf(scan); toast.success("Report exported"); }}>
              <FileDown className="h-4 w-4" /> Download PDF
            </Button>
          </>
        }
      />

      {/* 1. Executive summary */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">1. Executive Summary</CardTitle></CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p>
            Overall security posture score: <span className="font-mono font-semibold">{summary.overallScore}/100</span>.
            This assessment identified <b>{summary.findings.length}</b> findings across HTTP headers, cookies, TLS, CSRF, XSS,
            session handling, and reconnaissance surfaces.
          </p>
          <div className="flex flex-wrap gap-2">
            {(["Critical", "High", "Medium", "Low", "Info"] as RiskRating[]).map((r) => {
              const count = summary.totals[r.toLowerCase() as keyof typeof summary.totals];
              return (
                <Badge key={r} variant="outline" className={riskClass[r]}>
                  {r}: {count}
                </Badge>
              );
            })}
          </div>
          {summary.strengths.length > 0 && (
            <div>
              <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Observed strengths</div>
              <ul className="space-y-1">
                {summary.strengths.map((s) => <li key={s}>• {s}</li>)}
              </ul>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 2. Scope & methodology */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">2. Scope & Methodology</CardTitle></CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p><b>In-scope target:</b> <span className="font-mono">{summary.targetUrl}</span></p>
          <p>
            Methodology follows a seven-phase workflow adapted from OWASP WSTG, OSSTMM, PTES, and NIST SP 800-115:
            Scoping &amp; Rules of Engagement, Reconnaissance, Enumeration, Vulnerability Identification, Validation,
            Post-Validation Analysis, and Reporting. Testing is limited to passive and safe active checks issued by the
            NOVAIN Security Lab scanner against the authorized target only.
          </p>
        </CardContent>
      </Card>

      {/* 3. Asset inventory */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">3. Asset Inventory</CardTitle></CardHeader>
        <CardContent>
          <ul className="space-y-1 text-sm">
            {summary.assets.map((a) => <li key={a}>• {a}</li>)}
          </ul>
        </CardContent>
      </Card>

      {/* 4. Attack surface summary */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">4. Attack Surface Summary</CardTitle></CardHeader>
        <CardContent className="grid grid-cols-2 gap-3 text-sm md:grid-cols-3">
          <div><span className="text-muted-foreground">Headers:</span> {scan.headers.length}</div>
          <div><span className="text-muted-foreground">Cookies:</span> {scan.cookies.length}</div>
          <div><span className="text-muted-foreground">Forms:</span> {scan.csrf.length}</div>
          <div><span className="text-muted-foreground">XSS cases:</span> {scan.xss.length}</div>
          <div><span className="text-muted-foreground">Session checks:</span> {scan.sessions.length}</div>
          <div><span className="text-muted-foreground">Recon checks:</span> {scan.recon.length}</div>
        </CardContent>
      </Card>

      {/* 5. Findings */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">5. Confirmed Findings ({summary.findings.length})</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {summary.findings.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No confirmed findings from automated checks. Manual testing recommended for business-logic coverage.
            </p>
          ) : (
            summary.findings.map((f, i) => (
              <div key={f.id} className="rounded-md border border-border/60 bg-surface/40 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline" className={riskClass[f.risk]}>{f.risk}</Badge>
                  <span className="font-mono text-xs text-muted-foreground">CVSS {f.cvss.toFixed(1)}</span>
                  <span className="font-mono text-xs text-muted-foreground">·</span>
                  <span className="font-mono text-xs text-muted-foreground">{f.module}</span>
                </div>
                <h3 className="mt-1 text-sm font-semibold">{i + 1}. {f.title}</h3>
                <Separator className="my-3" />
                <div className="grid gap-3 md:grid-cols-3">
                  <div>
                    <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Impact</div>
                    <p className="text-sm">{f.impact}</p>
                  </div>
                  <div className="md:col-span-2">
                    <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Evidence</div>
                    <RawBlock title="evidence">{f.evidence}</RawBlock>
                  </div>
                  <div className="md:col-span-3">
                    <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Remediation</div>
                    <p className="text-sm">{f.remediation}</p>
                  </div>
                  <div className="md:col-span-3">
                    <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Proof of concept</div>
                    <FindingValidator finding={f} targetUrl={scan.targetUrl} />
                  </div>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      {/* 6. Risk assessment */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">6. Risk Assessment</CardTitle></CardHeader>
        <CardContent className="text-sm">
          Ratings combine automated severity with typical business impact: authentication and transport issues are treated as
          High, cookie flag issues and exposed endpoints as High/Medium, and hardening gaps (headers, meta files) as Low.
          CVSS values are indicative and should be re-scored per environment.
        </CardContent>
      </Card>

      {/* 7. Residual risks */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">7. Residual Risks</CardTitle></CardHeader>
        <CardContent className="text-sm">
          Automated scanning cannot confirm business-logic flaws, chained multi-step exploits, authenticated-only surfaces,
          or issues behind rate limits and WAFs. A manual engagement is recommended to cover authenticated workflows,
          privilege boundaries, and application-specific logic.
        </CardContent>
      </Card>
    </PageShell>
  );
}
