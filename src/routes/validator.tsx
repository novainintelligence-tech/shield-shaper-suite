import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PlayCircle, Loader2, FileDown, Target, ShieldAlert } from "lucide-react";

import { PageHeader, PageShell } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { RawBlock } from "@/components/raw-block";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { FindingValidator, isActiveFinding } from "@/components/finding-validator";
import { useLatestScan } from "@/hooks/use-scans";
import { buildFindings, type RiskRating } from "@/lib/engagement";
import { useServerFn } from "@tanstack/react-start";
import { runValidation, runStandalonePoc, POC_LIBRARY, type ValidationResult, type Verdict } from "@/lib/validator.functions";
import { toCurl } from "@/lib/validator-command";
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

const verdictClass: Record<Verdict, string> = {
  confirmed: "border-critical/50 text-critical bg-critical/10",
  "not-exploitable": "border-success/40 text-success bg-success/5",
  inconclusive: "border-warning/40 text-warning bg-warning/5",
  skipped: "border-border text-muted-foreground",
  error: "border-critical/50 text-critical bg-critical/10",
};

function ValidatorPage() {
  const { data: scan } = useLatestScan();
  const [authorize, setAuthorize] = useState(false);
  const [results, setResults] = useState<Record<string, ValidationResult>>({});
  const [batchBusy, setBatchBusy] = useState(false);
  const run = useServerFn(runValidation);
  const runStandalone = useServerFn(runStandalonePoc);

  const findings = useMemo(() => (scan ? buildFindings(scan) : []), [scan]);

  // Standalone probe state
  const [standaloneUrl, setStandaloneUrl] = useState<string>(scan?.targetUrl ?? "https://");
  const [standaloneResults, setStandaloneResults] = useState<Record<string, ValidationResult>>({});
  const [standaloneBusy, setStandaloneBusy] = useState<string | null>(null);
  const [standaloneBatchBusy, setStandaloneBatchBusy] = useState(false);

  const runOnePoc = async (pocId: string) => {
    try { new URL(standaloneUrl); } catch { toast.error("Enter a valid URL"); return; }
    setStandaloneBusy(pocId);
    try {
      const r = await runStandalone({ data: { url: standaloneUrl, pocId, authorizeActive: authorize } });
      setStandaloneResults((prev) => ({ ...prev, [pocId]: r }));
      if (r.verdict === "confirmed") toast.error(`Confirmed: ${pocId}`);
      else if (r.verdict === "not-exploitable") toast.success(`Not exploitable: ${pocId}`);
      else toast.info(`${pocId}: ${r.verdict}`);
    } catch (e) {
      toast.error(`Failed ${pocId}: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setStandaloneBusy(null);
    }
  };

  const runAllStandaloneSafe = async () => {
    try { new URL(standaloneUrl); } catch { toast.error("Enter a valid URL"); return; }
    setStandaloneBatchBusy(true);
    for (const p of POC_LIBRARY) {
      if (p.active && !authorize) continue;
      try {
        const r = await runStandalone({ data: { url: standaloneUrl, pocId: p.id, authorizeActive: authorize } });
        setStandaloneResults((prev) => ({ ...prev, [p.id]: r }));
      } catch { /* keep going */ }
    }
    setStandaloneBatchBusy(false);
    toast.success("Standalone batch complete");
  };

  const runAllSafe = async () => {
    if (!scan) return;
    setBatchBusy(true);
    const safe = findings.filter((f) => !isActiveFinding(f));
    for (const f of safe) {
      try {
        const pathHint = f.id.startsWith("recon-") ? f.evidence.match(/https?:\/\/[^\s]+/)?.[0] : undefined;
        const r = await run({ data: { findingId: f.id, targetUrl: scan.targetUrl, path: pathHint, authorizeActive: false } });
        setResults((prev) => ({ ...prev, [f.id]: r }));
      } catch { toast.error(`Failed: ${f.title}`); }
    }
    setBatchBusy(false);
    toast.success(`Ran ${safe.length} safe PoCs`);
  };

  const exportPdf = () => {
    if (!scan) return;
    const entries = findings
      .map((f) => ({ finding: f, result: results[f.id] }))
      .filter((e): e is { finding: typeof e.finding; result: ValidationResult } => Boolean(e.result));
    if (entries.length === 0) { toast.error("No validations to export", { description: "Run at least one PoC first." }); return; }
    try {
      downloadValidatorPdf(scan.targetHost, scan.targetUrl, entries);
      toast.success(`Exported ${entries.length} validation${entries.length === 1 ? "" : "s"}`);
    } catch (e) { toast.error("PDF export failed", { description: e instanceof Error ? e.message : String(e) }); }
  };

  return (
    <PageShell>
      <PageHeader
        eyebrow="Validation"
        title="PoC Validator"
        description={scan ? `${scan.targetHost} · re-issue requests against each finding, or run PoCs against any URL.` : "Run proof-of-concept probes against any authorized URL."}
        actions={
          <>
            <ScanRunner label={scan ? "Rescan" : "Run scan"} />
            {scan && (
              <>
                <Button size="sm" variant="outline" disabled={batchBusy || findings.length === 0} onClick={runAllSafe}>
                  {batchBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
                  Run all safe PoCs
                </Button>
                <Button size="sm" variant="outline" disabled={Object.keys(results).length === 0} onClick={exportPdf}>
                  <FileDown className="h-4 w-4" />
                  Export PDF
                </Button>
              </>
            )}
          </>
        }
      />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Rules of engagement</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p className="text-muted-foreground">
            Only run PoCs against systems you own or have explicit written authorization to test.
            Safe PoCs perform read-only probes. Active PoCs may issue state-changing requests.
          </p>
          <div className="flex items-center gap-2">
            <Checkbox id="auth-global" checked={authorize} onCheckedChange={(v) => setAuthorize(v === true)} />
            <Label htmlFor="auth-global" className="text-sm">
              I own or have written authorization to test the target URL and authorize active probes.
            </Label>
          </div>
        </CardContent>
      </Card>

      {/* Standalone URL probes */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <CardTitle className="text-sm flex items-center gap-2">
              <Target className="h-4 w-4 text-primary" /> Standalone probes · run against any URL
            </CardTitle>
            <Button size="sm" variant="outline" disabled={standaloneBatchBusy} onClick={runAllStandaloneSafe}>
              {standaloneBatchBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
              Run entire PoC library
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <Input
              value={standaloneUrl}
              onChange={(e) => setStandaloneUrl(e.target.value)}
              placeholder="https://example.com/path?query"
              className="h-9 font-mono text-xs flex-1 min-w-[280px]"
            />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            {POC_LIBRARY.map((p) => {
              const r = standaloneResults[p.id];
              const busy = standaloneBusy === p.id;
              return (
                <div key={p.id} className="rounded-md border border-border/60 bg-surface/40 p-3 space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium">{p.label}</span>
                        {p.active && (
                          <Badge variant="outline" className="border-critical/40 text-critical bg-critical/5 gap-1 text-[10px]">
                            <ShieldAlert className="h-3 w-3" /> Active
                          </Badge>
                        )}
                        {r && <Badge variant="outline" className={`${verdictClass[r.verdict]} text-[10px]`}>{r.verdict}</Badge>}
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">{p.desc}</p>
                    </div>
                    <Button size="sm" variant={p.active ? "destructive" : "outline"} disabled={busy || (p.active && !authorize)} onClick={() => runOnePoc(p.id)}>
                      {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <PlayCircle className="h-3.5 w-3.5" />}
                      Run
                    </Button>
                  </div>
                  {r && (
                    <div className="space-y-2 border-t border-border/60 pt-2">
                      <div className="text-xs">{r.summary}</div>
                      {r.steps.map((s, i) => (
                        <div key={i} className="space-y-1">
                          <div className="text-[11px] font-mono">{s.method} {s.url} → {s.status ?? "no response"}{s.error ? ` (${s.error})` : ""}</div>
                          <RawBlock title="curl">{toCurl(s)}</RawBlock>
                          {Object.keys(s.responseHeaders).length > 0 && (
                            <RawBlock title="response headers" maxHeight={140}>
                              {Object.entries(s.responseHeaders).map(([k, v]) => `${k}: ${v}`).join("\n")}
                            </RawBlock>
                          )}
                          {s.bodySnippet && (
                            <RawBlock title={`body (${s.bodyBytes}b${s.bodyTruncated ? " truncated" : ""})`} maxHeight={140}>{s.bodySnippet}</RawBlock>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Scan-driven findings section */}
      {scan ? (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Findings from latest scan ({findings.length})</CardTitle>
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
      ) : (
        <EmptyScanState context="scan-driven findings" />
      )}
    </PageShell>
  );
}
