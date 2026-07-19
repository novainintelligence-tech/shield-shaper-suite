import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScanRunner } from "@/components/scan-runner";
import { EmptyScanState } from "@/components/empty-scan-state";
import { useLatestScan } from "@/hooks/use-scans";

export const Route = createFileRoute("/csrf")({
  head: () => ({
    meta: [
      { title: "CSRF Validator · NSL" },
      { name: "description", content: "Scans HTML forms for CSRF tokens and pairs the result with the target's session cookie SameSite setting." },
    ],
  }),
  component: CsrfPage,
});

function CsrfPage() {
  const { data: latest } = useLatestScan();

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · CSRF"
        title="CSRF Validator"
        description="Passive scan of state-changing HTML forms plus SameSite session-cookie posture."
        actions={<ScanRunner />}
      />

      {!latest ? (
        <EmptyScanState context="CSRF" />
      ) : (
        <div className="grid gap-3">
          {latest.csrf.map((r, i) => (
            <Card key={`${r.endpoint}-${i}`}>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <div className="flex items-center gap-2">
                  <Badge className="font-mono">{r.method}</Badge>
                  <CardTitle className="font-mono text-sm">{r.endpoint}</CardTitle>
                </div>
                <SeverityBadge severity={r.severity} />
              </CardHeader>
              <CardContent className="grid gap-3 sm:grid-cols-3">
                <Field
                  label="Token in form"
                  value={r.tokenFound ? "yes" : "no"}
                  good={r.tokenFound}
                />
                <Field
                  label="Session SameSite"
                  value={r.sameSiteHint}
                  good={r.sameSiteHint === "Strict" || r.sameSiteHint === "Lax"}
                />
                <div className="sm:col-span-3">
                  <p className="text-xs text-muted-foreground">{r.note}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </PageShell>
  );
}

function Field({ label, value, good }: { label: string; value: string; good: boolean }) {
  return (
    <div>
      <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</p>
      <p className={`mt-1 font-mono text-sm ${good ? "text-success" : "text-critical"}`}>{value}</p>
    </div>
  );
}
