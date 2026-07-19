import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  ArrowUpRight,
  Cookie,
  Bug,
  ShieldAlert,
  KeyRound,
  ServerCog,
  LockKeyhole,
  ScrollText,
} from "lucide-react";

import { PageHeader, PageShell } from "@/components/page-header";
import { SeverityBadge, type Severity } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { mockAudit, mockScore, overallScore } from "@/lib/mock-data";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Dashboard · NOVAIN Security Lab" },
      {
        name: "description",
        content: "Overall posture, module scores, and recent authentication events across your stack.",
      },
    ],
  }),
  component: Dashboard,
});

const moduleCards: Array<{
  title: string;
  href: string;
  icon: typeof Cookie;
  score: number;
  severity: Severity;
  hint: string;
}> = [
  { title: "Cookie Inspector", href: "/cookies", icon: Cookie, score: mockScore.cookies, severity: "warn", hint: "1 insecure legacy cookie" },
  { title: "HTTP Headers", href: "/headers", icon: ServerCog, score: mockScore.headers, severity: "warn", hint: "X-Content-Type-Options missing" },
  { title: "TLS Checker", href: "/tls", icon: LockKeyhole, score: mockScore.tls, severity: "warn", hint: "Cert expires in 22 days" },
  { title: "Session Security", href: "/sessions", icon: KeyRound, score: mockScore.sessions, severity: "pass", hint: "All checks nominal" },
  { title: "CSRF Validator", href: "/csrf", icon: ShieldAlert, score: mockScore.csrf, severity: "fail", hint: "1 endpoint exposed" },
  { title: "XSS Test Suite", href: "/xss", icon: Bug, score: mockScore.xss, severity: "warn", hint: "JSON escaping gap" },
  { title: "Auth Audit", href: "/audit", icon: ScrollText, score: mockScore.auth, severity: "pass", hint: "No anomalies (24h)" },
];

function severityForScore(score: number): Severity {
  if (score >= 85) return "pass";
  if (score >= 70) return "warn";
  return "fail";
}

function Dashboard() {
  const overall = overallScore;
  const overallSeverity = severityForScore(overall);

  return (
    <PageShell>
      <PageHeader
        eyebrow="Overview"
        title="Security posture"
        description="A consolidated view across cookies, headers, TLS, sessions, CSRF/XSS defenses, and authentication events."
        actions={
          <>
            <Button variant="outline" size="sm">
              <Activity className="h-4 w-4" />
              Run all scans
            </Button>
            <Button size="sm">Export report</Button>
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Overall score
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-baseline gap-3">
              <span className="font-mono text-5xl font-semibold tracking-tight">{overall}</span>
              <span className="text-sm text-muted-foreground">/ 100</span>
              <SeverityBadge severity={overallSeverity} className="ml-auto">
                {overallSeverity === "pass" ? "Healthy" : overallSeverity === "warn" ? "Attention" : "At risk"}
              </SeverityBadge>
            </div>
            <Progress value={overall} className="h-2" />
            <p className="text-xs text-muted-foreground">
              Weighted average of 7 modules. Last full scan 4 minutes ago.
            </p>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Module breakdown
            </CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 sm:grid-cols-2">
            {Object.entries(mockScore).map(([k, v]) => {
              const s = severityForScore(v);
              return (
                <div key={k} className="rounded-md border border-border/60 bg-surface/50 p-3">
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span className="font-mono uppercase tracking-widest">{k}</span>
                    <SeverityBadge severity={s} />
                  </div>
                  <div className="mt-2 flex items-baseline gap-2">
                    <span className="font-mono text-2xl font-semibold">{v}</span>
                    <span className="text-xs text-muted-foreground">/ 100</span>
                  </div>
                  <Progress value={v} className="mt-2 h-1.5" />
                </div>
              );
            })}
          </CardContent>
        </Card>
      </div>

      <div>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-medium text-muted-foreground">Modules</h2>
        </div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {moduleCards.map((m) => (
            <Link
              key={m.href}
              to={m.href}
              className="group panel relative flex flex-col gap-3 p-4 transition hover:border-primary/40"
            >
              <div className="flex items-start justify-between">
                <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary/10 ring-1 ring-primary/30">
                  <m.icon className="h-4 w-4 text-primary" />
                </div>
                <ArrowUpRight className="h-4 w-4 text-muted-foreground transition group-hover:text-primary" />
              </div>
              <div>
                <div className="text-sm font-semibold">{m.title}</div>
                <p className="mt-0.5 text-xs text-muted-foreground">{m.hint}</p>
              </div>
              <div className="flex items-center justify-between">
                <span className="font-mono text-lg">{m.score}<span className="text-xs text-muted-foreground">/100</span></span>
                <SeverityBadge severity={m.severity} />
              </div>
            </Link>
          ))}
        </div>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-3">
          <div>
            <CardTitle className="text-sm font-medium">Recent authentication events</CardTitle>
            <p className="mt-1 text-xs text-muted-foreground">Last 24 hours across all tenants.</p>
          </div>
          <Button asChild variant="ghost" size="sm">
            <Link to="/audit">View audit log</Link>
          </Button>
        </CardHeader>
        <CardContent className="p-0">
          <div className="divide-y divide-border">
            {mockAudit.slice(0, 5).map((e) => (
              <div key={e.id} className="grid grid-cols-12 items-center gap-3 px-4 py-2.5 text-sm">
                <span className="col-span-3 font-mono text-xs text-muted-foreground">{e.time}</span>
                <span className="col-span-3 truncate">{e.actor}</span>
                <span className="col-span-4 truncate text-muted-foreground">{e.event}</span>
                <span className="col-span-2 text-right">
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
                </span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </PageShell>
  );
}
