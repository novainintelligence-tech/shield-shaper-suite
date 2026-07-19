import { createFileRoute } from "@tanstack/react-router";
import { Play } from "lucide-react";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { mockXss } from "@/lib/mock-data";

export const Route = createFileRoute("/xss")({
  head: () => ({
    meta: [
      { title: "XSS Test Suite · NSL" },
      { name: "description", content: "Validate reflected, stored, DOM XSS defenses plus CSP effectiveness and output encoding." },
    ],
  }),
  component: XssPage,
});

const categories = ["All", "Reflected", "Stored", "DOM", "CSP", "Encoding"] as const;

function XssPage() {
  return (
    <PageShell>
      <PageHeader
        eyebrow="Module · XSS"
        title="XSS Test Suite"
        description="Confirms your defenses block malicious input across common sinks. Focus is on protection, not exploitation."
        actions={
          <Button size="sm">
            <Play className="h-4 w-4" />
            Run suite
          </Button>
        }
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">Test cases</CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="All">
            <TabsList>
              {categories.map((c) => (
                <TabsTrigger key={c} value={c} className="text-xs">
                  {c}
                </TabsTrigger>
              ))}
            </TabsList>

            {categories.map((c) => {
              const rows = c === "All" ? mockXss : mockXss.filter((r) => r.category === c);
              return (
                <TabsContent key={c} value={c} className="mt-4 space-y-3">
                  {rows.map((r) => (
                    <div key={r.id} className="rounded-md border border-border/60 bg-surface/40 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs text-muted-foreground">{r.id}</span>
                          <Badge variant="secondary" className="text-[10px]">{r.category}</Badge>
                          <span className="text-sm">{r.vector}</span>
                        </div>
                        <SeverityBadge severity={r.severity} />
                      </div>
                      <pre className="mt-2 overflow-x-auto rounded bg-background/70 p-2 font-mono text-xs text-muted-foreground ring-1 ring-border">
                        {r.payload}
                      </pre>
                      <p className="mt-2 text-xs text-muted-foreground">{r.detail}</p>
                    </div>
                  ))}
                </TabsContent>
              );
            })}
          </Tabs>
        </CardContent>
      </Card>
    </PageShell>
  );
}
