import { createFileRoute } from "@tanstack/react-router";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { mockSessions } from "@/lib/mock-data";

export const Route = createFileRoute("/sessions")({
  head: () => ({
    meta: [
      { title: "Session Security · NSL" },
      { name: "description", content: "Verify session rotation, logout invalidation, idle timeout, absolute lifetime, and multi-device handling." },
    ],
  }),
  component: SessionsPage,
});

function SessionsPage() {
  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · Sessions"
        title="Session Security"
        description="Behavior tests for the target's session lifecycle."
      />
      <div className="grid gap-3 md:grid-cols-2">
        {mockSessions.map((s) => (
          <Card key={s.name}>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm">{s.name}</CardTitle>
              <SeverityBadge severity={s.status} />
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">{s.observation}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </PageShell>
  );
}
