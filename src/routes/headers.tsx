import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { useLatestScan } from "@/hooks/use-scans";

export const Route = createFileRoute("/headers")({
  head: () => ({
    meta: [
      { title: "HTTP Security Scanner · NSL" },
      { name: "description", content: "Audit response headers: CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-Content-Type-Options." },
    ],
  }),
  component: HeadersPage,
});

function HeadersPage() {
  const { data: latest } = useLatestScan();

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Headers"
        title="HTTP Security Scanner"
        description="Response header audit against modern hardening baselines."
        actions={<ScanRunner />}
      />

      {!latest ? (
        <EmptyScanState context="header" />
      ) : (
        <div className="grid gap-3">
          {latest.headers.map((h) => (
            <Card key={h.name}>
              <CardHeader className="flex flex-row items-start justify-between gap-3 pb-2">
                <div>
                  <CardTitle className="font-mono text-sm">{h.name}</CardTitle>
                  <p className="mt-1 font-mono text-xs text-muted-foreground">
                    expected · {h.expected}
                  </p>
                </div>
                <SeverityBadge severity={h.severity} />
              </CardHeader>
              <CardContent className="space-y-2">
                {h.value ? (
                  <pre className="overflow-x-auto rounded bg-background/70 p-2 font-mono text-xs ring-1 ring-border">
                    {h.value}
                  </pre>
                ) : (
                  <p className="font-mono text-xs italic text-critical">— header not present —</p>
                )}
                <p className="text-xs text-muted-foreground">{h.note}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </PageShell>
  );
}
