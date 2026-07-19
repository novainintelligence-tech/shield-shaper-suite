import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { RefreshCw } from "lucide-react";
import { mockCsrf } from "@/lib/mock-data";

export const Route = createFileRoute("/csrf")({
  head: () => ({
    meta: [
      { title: "CSRF Validator · NSL" },
      { name: "description", content: "Verify CSRF token enforcement and SameSite cookie behavior on state-changing endpoints." },
    ],
  }),
  component: CsrfPage,
});

function CsrfPage() {
  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · CSRF"
        title="CSRF Validator"
        description="Ensures state-changing endpoints require valid CSRF protection and that SameSite cookies behave as configured."
        actions={
          <Button size="sm" variant="outline">
            <RefreshCw className="h-4 w-4" /> Re-run
          </Button>
        }
      />

      <div className="grid gap-3">
        {mockCsrf.map((r) => (
          <Card key={r.endpoint}>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <div className="flex items-center gap-2">
                <Badge className="font-mono">{r.method}</Badge>
                <CardTitle className="font-mono text-sm">{r.endpoint}</CardTitle>
              </div>
              <SeverityBadge severity={r.severity} />
            </CardHeader>
            <CardContent className="grid gap-3 sm:grid-cols-4">
              <Field label="Token required" value={r.tokenRequired ? "yes" : "no"} good={r.tokenRequired} />
              <Field label="Token validated" value={r.tokenValidated ? "yes" : "no"} good={r.tokenValidated} />
              <Field label="SameSite" value={r.sameSite} good={r.sameSite === "Strict" || r.sameSite === "Lax"} />
              <div className="sm:col-span-4">
                <p className="text-xs text-muted-foreground">{r.note}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
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
