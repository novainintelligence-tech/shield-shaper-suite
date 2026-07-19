import { createFileRoute } from "@tanstack/react-router";
import { Check, X, RefreshCw } from "lucide-react";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { mockCookies } from "@/lib/mock-data";

export const Route = createFileRoute("/cookies")({
  head: () => ({
    meta: [
      { title: "Cookie Inspector · NSL" },
      { name: "description", content: "Inspect cookie flags: HttpOnly, Secure, SameSite, domain, path, expiration, and JS reachability." },
    ],
  }),
  component: CookiesPage,
});

function Flag({ on }: { on: boolean }) {
  return on ? (
    <Check className="h-4 w-4 text-success" />
  ) : (
    <X className="h-4 w-4 text-critical" />
  );
}

function CookiesPage() {
  const total = mockCookies.length;
  const pass = mockCookies.filter((c) => c.severity === "pass").length;
  const fail = mockCookies.filter((c) => c.severity === "fail").length;

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Cookies"
        title="Cookie Inspector"
        description="Every cookie set by the target, with flag audit and JavaScript-accessibility status."
        actions={
          <Button size="sm" variant="outline">
            <RefreshCw className="h-4 w-4" />
            Re-scan
          </Button>
        }
      />

      <div className="grid gap-3 sm:grid-cols-3">
        {[
          { label: "Total cookies", value: total },
          { label: "Compliant", value: pass, tone: "text-success" },
          { label: "Failing", value: fail, tone: "text-critical" },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-6">
              <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                {s.label}
              </p>
              <p className={`mt-1 font-mono text-3xl font-semibold ${s.tone ?? ""}`}>{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Cookies</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Domain</TableHead>
                  <TableHead>Path</TableHead>
                  <TableHead className="text-center">HttpOnly</TableHead>
                  <TableHead className="text-center">Secure</TableHead>
                  <TableHead>SameSite</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead className="text-center">JS</TableHead>
                  <TableHead className="text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mockCookies.map((c) => (
                  <TableRow key={c.name}>
                    <TableCell className="font-mono text-xs">{c.name}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{c.domain}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{c.path}</TableCell>
                    <TableCell className="text-center"><Flag on={c.httpOnly} /></TableCell>
                    <TableCell className="text-center"><Flag on={c.secure} /></TableCell>
                    <TableCell>
                      <span
                        className={
                          c.sameSite === "Missing" || c.sameSite === "None"
                            ? "font-mono text-xs text-warning"
                            : "font-mono text-xs"
                        }
                      >
                        {c.sameSite}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{c.expires}</TableCell>
                    <TableCell className="text-center">
                      {c.jsAccessible ? (
                        <span className="font-mono text-xs text-warning">reachable</span>
                      ) : (
                        <span className="font-mono text-xs text-success">blocked</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right"><SeverityBadge severity={c.severity} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </PageShell>
  );
}
