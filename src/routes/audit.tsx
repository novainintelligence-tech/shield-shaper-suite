import { createFileRoute } from "@tanstack/react-router";
import { Download, Search } from "lucide-react";
import { useMemo, useState } from "react";

import { PageHeader, PageShell } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { mockAudit } from "@/lib/mock-data";

export const Route = createFileRoute("/audit")({
  head: () => ({
    meta: [
      { title: "Authentication Audit · NSL" },
      { name: "description", content: "Immutable log of authentication events: logins, MFA, password changes, session lifecycle." },
    ],
  }),
  component: AuditPage,
});

function AuditPage() {
  const [q, setQ] = useState("");
  const filtered = useMemo(
    () => mockAudit.filter((e) => (q ? [e.actor, e.event, e.ip].join(" ").toLowerCase().includes(q.toLowerCase()) : true)),
    [q],
  );

  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Audit"
        title="Authentication Audit"
        description="Immutable record of authentication and session events across the target."
        actions={
          <Button size="sm" variant="outline">
            <Download className="h-4 w-4" /> Export CSV
          </Button>
        }
      />

      <Card>
        <CardContent className="p-0">
          <div className="flex items-center gap-2 border-b border-border p-3">
            <Search className="h-4 w-4 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Filter by actor, event, or IP"
              className="h-8 border-0 bg-transparent px-0 font-mono text-xs shadow-none focus-visible:ring-0"
            />
          </div>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Event</TableHead>
                  <TableHead className="text-right">Result</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="font-mono text-xs text-muted-foreground">{e.time}</TableCell>
                    <TableCell className="text-sm">{e.actor}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{e.ip}</TableCell>
                    <TableCell className="text-sm">{e.event}</TableCell>
                    <TableCell className="text-right">
                      <Badge
                        variant="outline"
                        className={
                          e.result === "success"
                            ? "border-success/40 text-success"
                            : e.result === "failure"
                            ? "border-critical/40 text-critical"
                            : "border-info/40 text-info"
                        }
                      >
                        {e.result}
                      </Badge>
                    </TableCell>
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
