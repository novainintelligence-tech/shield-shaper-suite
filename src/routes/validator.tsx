import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PlayCircle, Loader2, FileDown } from "lucide-react";

import { PageHeader, PageShell } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { FindingValidator, isActiveFinding } from "@/components/finding-validator";
import { useLatestScan } from "@/hooks/use-scans";
import { buildFindings, type RiskRating } from "@/lib/engagement";
import { useServerFn } from "@tanstack/react-start";
import { runValidation, type ValidationResult } from "@/lib/validator.functions";
import { downloadValidatorPdf } from "@/lib/validator-pdf";
import { toast } from "sonner";

export const Route = createFileRoute("/validator")({
  head: () => ({
    meta: [
      { title: "PoC Validator · NOVAIN Security Lab" },
      { name: "description", content: "Execute proof-of-concept validation against every finding from the latest scan to distinguish confirmed vulnerabilities from theoretical ones." },
    ],
  }),
  component: ValidatorPage,
});

const riskClass: Record<RiskRating, string> = {
  Critical: "border-critical/50 text-critical bg-critical/10",
  High: "border-critical/40 text-critical bg-critical/5",
  Medium: "border-warning/40 text-warning bg-warning/5",
  Low: "border-success/40 text-success bg-success/5",
  Info: "border-border text-muted-foreground",
};

function ValidatorPage() {
  const { data: scan } = useLatestScan();
  const [authorize, setAuthorize] = useState(false);
  const [results, setResults] = useState<Record<string, ValidationResult>>({});
  const [batchBusy, setBatchBusy] = useState(false);
  const run = useServerFn(runValidation);

  const findings = useMemo(() => (scan ? buildFindings(scan) : []), [scan]);

  if (!scan) {
    return (
      <PageShell>
        <PageHeader
          eyebrow="Validation"
          title="PoC Validator"
          description="Re-execute the exact requests needed to prove each finding is real."
          actions={<ScanRunner label="Run scan" />}
        />
        <EmptyScanState context="the PoC validator" />
      </PageShell>
    );
  }

  const runAllSafe = async () => {
    setBatchBusy(true);
    const safe = findings.filter((f) => !isActiveFinding(f));
    for (const f of safe) {
      try {
        const pathHint =
          f.id.startsWith("recon-") ? f.evidence.match(/https?:\/\/[^\s]+/)?.[0] : undefined;
        const r = await run({ data: { findingId: f.id, targetUrl: scan.targetUrl, path: pathHint, authorizeActive: false } });
        setResults((prev) => ({ ...prev, [f.id]: r }));
      } catch (e) {
        toast.error(`Failed: ${f.title}`);
      }
    }
    setBatchBusy(false);
    toast.success(`Ran ${safe.length} safe PoCs`);
  };

  const exportPdf = () => {
    const entries = findings
      .map((f) => ({ finding: f, result: results[f.id] }))
      .filter((e): e is { finding: typeof e.finding; result: ValidationResult } => Boolean(e.result));
    if (entries.length === 0) {
      toast.error("No validations to export", { description: "Run at least one PoC first." });
      return;
    }
    try {
      downloadValidatorPdf(scan.targetHost, scan.targetUrl, entries);
      toast.success(`Exported ${entries.length} validation${entries.length === 1 ? "" : "s"}`);
    } catch (e) {
      toast.error("PDF export failed", { description: e instanceof Error ? e.message : String(e) });
    }
  };

  return (
    <PageShell>
      <PageHeader
        eyebrow="Validation"
        title="PoC Validator"
        description={`${scan.targetHost} · re-issue requests against each finding to prove exploitability.`}
        actions={
          <>
            <ScanRunner label="Rescan" />
            <Button size="sm" variant="outline" disabled={batchBusy || findings.length === 0} onClick={runAllSafe}>
              {batchBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
              Run all safe PoCs
            </Button>
            <Button size="sm" variant="outline" disabled={Object.keys(results).length === 0} onClick={exportPdf}>
              <FileDown className="h-4 w-4" />
              Export PDF
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Rules of engagement</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p className="text-muted-foreground">
            Every PoC targets the scanned host only. Safe PoCs perform read-only or benign probes.
            Active PoCs may issue state-changing requests and require explicit authorization.
          </p>
          <div className="flex items-center gap-2">
            <Checkbox id="auth-global" checked={authorize} onCheckedChange={(v) => setAuthorize(v === true)} />
            <Label htmlFor="auth-global" className="text-sm">
              I own <span className="font-mono">{scan.targetHost}</span> and authorize active exploitation testing.
            </Label>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Findings ({findings.length})</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {findings.length === 0 ? (
            <p className="text-sm text-muted-foreground">No findings to validate. The latest scan is clean.</p>
          ) : (
            findings.map((f, i) => (
              <div key={f.id} className="rounded-md border border-border/60 bg-surface/40 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline" className={riskClass[f.risk]}>{f.risk}</Badge>
                  <span className="font-mono text-xs text-muted-foreground">CVSS {f.cvss.toFixed(1)}</span>
                  <span className="font-mono text-xs text-muted-foreground">·</span>
                  <span className="font-mono text-xs text-muted-foreground">{f.module}</span>
                </div>
                <h3 className="mt-1 text-sm font-semibold">{i + 1}. {f.title}</h3>
                <Separator className="my-3" />
                <FindingValidator
                  finding={f}
                  targetUrl={scan.targetUrl}
                  globalAuthorize={authorize}
                  presetResult={results[f.id] ?? null}
                  onResult={(r) => setResults((prev) => ({ ...prev, [f.id]: r }))}
                />
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </PageShell>
  );
}
