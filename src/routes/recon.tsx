import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { useLatestScan } from "@/hooks/use-scans";
import type { ReconCategory } from "@/lib/scan-types";

export const Route = createFileRoute("/recon")({
  head: () => ({
    meta: [
      { title: "Reconnaissance · NSL" },
      { name: "description", content: "Exposed files, security.txt, robots, mixed content, and HTTP→HTTPS redirect posture." },
    ],
  }),
  component: ReconPage,
});

const CATEGORY_LABEL: Record<ReconCategory, string> = {
  meta: "Metadata & Disclosure",
  exposure: "Sensitive Path Exposure",
  "mixed-content": "Mixed Content",
  redirect: "Redirect / TLS Enforcement",
};

function ReconPage() {
  const { data: latest } = useLatestScan();

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Recon"
        title="Reconnaissance"
        description="Active probes for exposed files, security metadata, mixed content, and HTTP-to-HTTPS enforcement."
        actions={<ScanRunner />}
      />

      {!latest ? (
        <EmptyScanState context="reconnaissance" />
      ) : (
        <div className="grid gap-4">
          {(Object.keys(CATEGORY_LABEL) as ReconCategory[]).map((cat) => {
            const items = latest.recon.filter((r) => r.category === cat);
            if (items.length === 0) return null;
            return (
              <Card key={cat}>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">{CATEGORY_LABEL[cat]}</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {items.map((r) => (
                    <div key={r.id} className="rounded-md border border-border/60 bg-surface/40 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">{r.name}</span>
                          {r.target && (
                            <Badge variant="secondary" className="font-mono text-[10px]">{r.target}</Badge>
                          )}
                        </div>
                        <SeverityBadge severity={r.severity} />
                      </div>
                      <p className="mt-1 text-xs text-muted-foreground">{r.note}</p>
                    </div>
                  ))}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </PageShell>
  );
}
