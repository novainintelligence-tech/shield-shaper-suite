import { createFileRoute } from "@tanstack/react-router";
import { Download, Search } from "lucide-react";
import { useMemo, useState } from "react";

import { PageHeader, PageShell } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyScanState } from "@/components/empty-scan-state";
import { useRecentScans } from "@/hooks/use-scans";

export const Route = createFileRoute("/audit")({
  head: () => ({
    meta: [
      { title: "Scan History · NSL" },
      { name: "description", content: "Immutable log of every security scan run from this account." },
    ],
  }),
  component: AuditPage,
});

function AuditPage() {
  const [q, setQ] = useState("");
  const { data: history } = useRecentScans();

  const filtered = useMemo(
    () =>
      (history ?? []).filter((e) =>
        q
          ? [e.targetHost, e.targetUrl, e.status, String(e.overallScore)]
              .join(" ")
              .toLowerCase()
              .includes(q.toLowerCase())
          : true,
      ),
    [q, history],
  );

  const exportCsv = () => {
    const rows = [
      ["time", "host", "url", "status", "score", "duration_ms"],
      ...filtered.map((e) => [
        e.createdAt,
        e.targetHost,
        e.targetUrl,
        e.status,
        String(e.overallScore),
        String(e.durationMs ?? ""),
      ]),
    ];
    const csv = rows.map((r) => r.map((c) => `"${c.replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nsl-scans-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Audit"
        title="Scan History"
        description="Every scan you have run, saved to your account."
        actions={
          <Button size="sm" variant="outline" onClick={exportCsv} disabled={filtered.length === 0}>
            <Download className="h-4 w-4" /> Export CSV
          </Button>
        }
      />

      {!history || history.length === 0 ? (
        <EmptyScanState context="audit" />
      ) : (
        <Card>
          <CardContent className="p-0">
            <div className="flex items-center gap-2 border-b border-border p-3">
              <Search className="h-4 w-4 text-muted-foreground" />
              <Input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Filter by host, URL, or status"
                className="h-8 border-0 bg-transparent px-0 font-mono text-xs shadow-none focus-visible:ring-0"
              />
            </div>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Host</TableHead>
                    <TableHead>URL</TableHead>
                    <TableHead className="text-right">Score</TableHead>
                    <TableHead className="text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map((e) => (
                    <TableRow key={e.id}>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {new Date(e.createdAt).toLocaleString()}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{e.targetHost}</TableCell>
                      <TableCell className="truncate font-mono text-xs text-muted-foreground max-w-[420px]">
                        {e.targetUrl}
                      </TableCell>
                      <TableCell className="text-right font-mono">{e.overallScore}</TableCell>
                      <TableCell className="text-right">
                        <Badge
                          variant="outline"
                          className={
                            e.status === "complete"
                              ? "border-success/40 text-success"
                              : "border-critical/40 text-critical"
                          }
                        >
                          {e.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}
    </PageShell>
  );
}
