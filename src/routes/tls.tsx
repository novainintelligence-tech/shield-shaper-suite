import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { mockTls } from "@/lib/mock-data";

export const Route = createFileRoute("/tls")({
  head: () => ({
    meta: [
      { title: "TLS Checker · NSL" },
      { name: "description", content: "TLS version, cipher suite, certificate chain, and expiration warnings for the target host." },
    ],
  }),
  component: TlsPage,
});

function TlsPage() {
  const t = mockTls;
  const daysPct = Math.max(0, Math.min(100, (t.daysRemaining / 90) * 100));

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · TLS"
        title="TLS Checker"
        description="Live TLS handshake introspection and certificate chain validation."
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div>
              <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                Host
              </p>
              <CardTitle className="font-mono text-lg">{t.host}</CardTitle>
              <p className="font-mono text-xs text-muted-foreground">{t.ip}</p>
            </div>
            <SeverityBadge severity={t.severity} />
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <Field label="Protocol" value={t.protocol} />
            <Field label="Cipher suite" value={t.cipher} mono />
            <Field label="Issuer" value={t.issuer} />
            <Field label="Valid from → to" value={`${t.validFrom} → ${t.validTo}`} mono />
            <Field label="HSTS preloaded" value={t.hstsPreloaded ? "yes" : "no"} good={t.hstsPreloaded} />
            <Field label="OCSP stapling" value={t.ocspStapling ? "enabled" : "disabled"} good={t.ocspStapling} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Expiration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-4xl font-semibold text-warning">{t.daysRemaining}</span>
              <span className="text-sm text-muted-foreground">days remaining</span>
            </div>
            <Progress value={daysPct} className="h-2" />
            <p className="text-xs text-muted-foreground">
              Renewal recommended within 14 days to avoid downtime.
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Certificate chain</CardTitle>
        </CardHeader>
        <CardContent>
          <ol className="space-y-2">
            {t.chain.map((c, i) => (
              <li key={c} className="flex items-center gap-3">
                <span className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 font-mono text-[10px] text-primary ring-1 ring-primary/30">
                  {i}
                </span>
                <span className="font-mono text-sm">{c}</span>
                {i < t.chain.length - 1 && <span className="text-muted-foreground">→</span>}
              </li>
            ))}
          </ol>
        </CardContent>
      </Card>
    </PageShell>
  );
}

function Field({ label, value, mono, good }: { label: string; value: string; mono?: boolean; good?: boolean }) {
  return (
    <div>
      <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</p>
      <p
        className={`mt-1 text-sm ${mono ? "font-mono" : ""} ${
          good === true ? "text-success" : good === false ? "text-critical" : ""
        }`}
      >
        {value}
      </p>
    </div>
  );
}
