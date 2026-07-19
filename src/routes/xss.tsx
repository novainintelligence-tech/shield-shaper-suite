import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { useLatestScan } from "@/hooks/use-scans";

export const Route = createFileRoute("/xss")({
  head: () => ({
    meta: [
      { title: "XSS Test Suite · NSL" },
      { name: "description", content: "Evaluates CSP and MIME-sniffing posture against the primary XSS execution paths." },
    ],
  }),
  component: XssPage,
});

function XssPage() {
  const { data: latest } = useLatestScan();

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · XSS"
        title="XSS Test Suite"
        description="Focused on protection: CSP shape and MIME-sniffing controls that block injected script execution."
        actions={<ScanRunner />}
      />

      {!latest ? (
        <EmptyScanState context="XSS" />
      ) : (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Findings for {latest.targetHost}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {latest.xss.map((r) => (
              <div key={r.id} className="rounded-md border border-border/60 bg-surface/40 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-muted-foreground">{r.id}</span>
                    <Badge variant="secondary" className="text-[10px]">
                      {r.category}
                    </Badge>
                    <span className="text-sm">{r.vector}</span>
                  </div>
                  <SeverityBadge severity={r.severity} />
                </div>
                <p className="mt-2 text-xs text-muted-foreground">{r.detail}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </PageShell>
  );
}
