import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { RefreshCw } from "lucide-react";
import { mockHeaders } from "@/lib/mock-data";

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
  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Headers"
        title="HTTP Security Scanner"
        description="Response header audit against modern hardening baselines."
        actions={
          <Button size="sm" variant="outline">
            <RefreshCw className="h-4 w-4" /> Re-scan
          </Button>
        }
      />

      <div className="grid gap-3">
        {mockHeaders.map((h) => (
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
    </PageShell>
  );
}
