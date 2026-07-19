import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import type {
  CookieRow,
  CsrfCheck,
  HeaderRow,
  ScanResult,
  ScoreBreakdown,
  SessionCheck,
  TlsResult,
  XssCase,
} from "./scan-types";
import type { Severity } from "@/components/severity-badge";

const urlSchema = z.object({
  url: z.string().url().refine(
    (u) => u.startsWith("http://") || u.startsWith("https://"),
    "URL must start with http:// or https://",
  ),
});

// ---------- Header analysis ----------

interface HeaderSpec {
  name: string;
  expected: string;
  evaluate: (value: string | null) => { severity: Severity; note: string };
}

const HEADER_SPECS: HeaderSpec[] = [
  {
    name: "Content-Security-Policy",
    expected: "Strict CSP without unsafe-inline / unsafe-eval",
    evaluate: (v) => {
      if (!v) return { severity: "fail", note: "No CSP header. Page can execute arbitrary inline/injected scripts." };
      const lower = v.toLowerCase();
      const bad: string[] = [];
      if (lower.includes("'unsafe-inline'")) bad.push("unsafe-inline");
      if (lower.includes("'unsafe-eval'")) bad.push("unsafe-eval");
      if (lower.includes("*")) bad.push("wildcard source");
      if (bad.length) return { severity: "warn", note: `Present but weakened: ${bad.join(", ")}.` };
      return { severity: "pass", note: "Strict CSP detected." };
    },
  },
  {
    name: "Strict-Transport-Security",
    expected: "max-age ≥ 15552000; includeSubDomains; preload",
    evaluate: (v) => {
      if (!v) return { severity: "fail", note: "HSTS missing. Downgrade attacks are possible." };
      const m = /max-age=(\d+)/i.exec(v);
      const maxAge = m ? Number(m[1]) : 0;
      if (maxAge < 15552000) return { severity: "warn", note: `max-age=${maxAge} is below the recommended 6-month minimum.` };
      return { severity: "pass", note: `HSTS enforced (max-age=${maxAge}).` };
    },
  },
  {
    name: "X-Frame-Options",
    expected: "DENY or SAMEORIGIN",
    evaluate: (v) => {
      if (!v) return { severity: "warn", note: "Missing. Consider CSP frame-ancestors directive instead." };
      const upper = v.toUpperCase();
      if (upper.includes("DENY") || upper.includes("SAMEORIGIN"))
        return { severity: "pass", note: "Clickjacking protection is active." };
      return { severity: "warn", note: `Unusual value: ${v}` };
    },
  },
  {
    name: "Referrer-Policy",
    expected: "no-referrer or strict-origin-when-cross-origin",
    evaluate: (v) => {
      if (!v) return { severity: "warn", note: "Missing. Browsers may leak full referrer URLs cross-origin." };
      return { severity: "pass", note: `Referrer-Policy: ${v}` };
    },
  },
  {
    name: "Permissions-Policy",
    expected: "Explicit deny for unused features",
    evaluate: (v) => {
      if (!v) return { severity: "warn", note: "Missing. Camera/microphone/geolocation are implicitly allowed." };
      return { severity: "pass", note: "Permissions-Policy present." };
    },
  },
  {
    name: "X-Content-Type-Options",
    expected: "nosniff",
    evaluate: (v) => {
      if (!v) return { severity: "fail", note: "Header missing. Browsers may MIME-sniff responses." };
      if (v.toLowerCase().includes("nosniff")) return { severity: "pass", note: "nosniff enforced." };
      return { severity: "warn", note: `Unexpected value: ${v}` };
    },
  },
];

function analyseHeaders(headers: Headers): HeaderRow[] {
  return HEADER_SPECS.map((spec) => {
    const value = headers.get(spec.name);
    const { severity, note } = spec.evaluate(value);
    return { name: spec.name, value, expected: spec.expected, severity, note };
  });
}

// ---------- Cookie parsing ----------

function parseSetCookies(setCookies: string[], host: string): CookieRow[] {
  return setCookies.map((raw) => {
    const parts = raw.split(";").map((p) => p.trim());
    const [nameEq, ...attrs] = parts;
    const eqIdx = nameEq.indexOf("=");
    const name = eqIdx > 0 ? nameEq.slice(0, eqIdx) : nameEq;

    let httpOnly = false;
    let secure = false;
    let sameSite: CookieRow["sameSite"] = "Missing";
    let domain = host;
    let path = "/";
    let expires = "Session";

    for (const attr of attrs) {
      const [k, v] = attr.split("=").map((s) => s?.trim());
      const key = k.toLowerCase();
      if (key === "httponly") httpOnly = true;
      else if (key === "secure") secure = true;
      else if (key === "samesite" && v) {
        const norm = v.charAt(0).toUpperCase() + v.slice(1).toLowerCase();
        if (norm === "Strict" || norm === "Lax" || norm === "None") sameSite = norm;
      } else if (key === "domain" && v) domain = v;
      else if (key === "path" && v) path = v;
      else if (key === "max-age" && v) expires = `${v}s`;
      else if (key === "expires" && v) expires = v;
    }

    let severity: Severity = "pass";
    if (!secure || sameSite === "None") severity = "fail";
    else if (!httpOnly || sameSite === "Missing") severity = "warn";

    return {
      name,
      domain,
      path,
      httpOnly,
      secure,
      sameSite,
      expires,
      jsAccessible: !httpOnly,
      severity,
    };
  });
}

// ---------- TLS ----------

function analyseTls(url: URL, headers: Headers): TlsResult {
  const scheme = url.protocol === "https:" ? "https" : "http";
  const hstsHeader = headers.get("strict-transport-security");
  const maxAgeMatch = hstsHeader ? /max-age=(\d+)/i.exec(hstsHeader) : null;
  const hstsMaxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : null;
  const includeSub = !!hstsHeader && /includesubdomains/i.test(hstsHeader);
  const preload = !!hstsHeader && /preload/i.test(hstsHeader);

  let severity: Severity = "pass";
  let note = "TLS enforced.";
  if (scheme === "http") {
    severity = "fail";
    note = "Target is served over plain HTTP.";
  } else if (!hstsHeader) {
    severity = "warn";
    note = "HTTPS in use, but no HSTS to prevent downgrade attacks.";
  } else if (!hstsMaxAge || hstsMaxAge < 15552000) {
    severity = "warn";
    note = `HSTS present but max-age is only ${hstsMaxAge}s.`;
  }

  return {
    host: url.host,
    scheme,
    hstsPresent: !!hstsHeader,
    hstsPreloaded: preload,
    hstsMaxAge,
    hstsIncludeSubDomains: includeSub,
    issuer: null,
    validFrom: null,
    validTo: null,
    daysRemaining: null,
    severity,
    note,
  };
}

async function enrichTlsWithCert(tls: TlsResult): Promise<TlsResult> {
  if (tls.scheme !== "https") return tls;
  try {
    const res = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(tls.host)}&output=json`,
      { signal: AbortSignal.timeout(6000) },
    );
    if (!res.ok) return tls;
    const rows = (await res.json()) as Array<{
      issuer_name?: string;
      not_before?: string;
      not_after?: string;
    }>;
    if (!Array.isArray(rows) || rows.length === 0) return tls;
    // Pick the most recently issued that hasn't expired.
    const now = Date.now();
    const active = rows
      .filter((r) => r.not_after && new Date(r.not_after).getTime() > now)
      .sort((a, b) => new Date(b.not_before!).getTime() - new Date(a.not_before!).getTime());
    const chosen = active[0] ?? rows[0];
    if (!chosen?.not_after) return tls;
    const daysRemaining = Math.round(
      (new Date(chosen.not_after).getTime() - now) / (1000 * 60 * 60 * 24),
    );
    let severity = tls.severity;
    let note = tls.note;
    if (daysRemaining < 14) {
      severity = "fail";
      note = `Certificate expires in ${daysRemaining} days.`;
    } else if (daysRemaining < 30 && severity === "pass") {
      severity = "warn";
      note = `Certificate expires in ${daysRemaining} days.`;
    }
    return {
      ...tls,
      issuer: chosen.issuer_name?.split(",").find((p) => p.trim().startsWith("O="))?.replace(/^\s*O=/, "") ?? chosen.issuer_name ?? null,
      validFrom: chosen.not_before ?? null,
      validTo: chosen.not_after ?? null,
      daysRemaining,
      severity,
      note,
    };
  } catch {
    return tls;
  }
}

// ---------- CSRF (passive HTML form scan) ----------

function analyseCsrf(html: string, cookies: CookieRow[], baseUrl: URL): CsrfCheck[] {
  const forms: CsrfCheck[] = [];
  const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let match: RegExpExecArray | null;
  const sessionCookie = cookies.find((c) => /session|sid|auth|jwt|token/i.test(c.name));
  const sameSiteHint: CsrfCheck["sameSiteHint"] = sessionCookie
    ? (sessionCookie.sameSite === "Missing" ? "Unknown" : sessionCookie.sameSite)
    : "Unknown";

  while ((match = formRegex.exec(html)) !== null) {
    const attrs = match[1];
    const body = match[2];
    const methodMatch = /method\s*=\s*["']?(\w+)/i.exec(attrs);
    const method = (methodMatch?.[1]?.toUpperCase() ?? "GET") as CsrfCheck["method"];
    const actionMatch = /action\s*=\s*["']([^"']*)/i.exec(attrs);
    const action = actionMatch?.[1] ?? "";
    let endpoint = action || baseUrl.pathname;
    try { endpoint = new URL(action || baseUrl.pathname, baseUrl).pathname; } catch { /* ignore */ }

    if (method === "GET") continue; // Only state-changing forms matter for CSRF.

    const tokenFound = /<input[^>]+(name|id)\s*=\s*["'][^"']*(csrf|token|authenticity)[^"']*["']/i.test(body);

    let severity: Severity = "pass";
    let note = "Hidden CSRF token detected on form.";
    if (!tokenFound && sameSiteHint === "Strict") {
      severity = "warn";
      note = "No CSRF token, but session cookie is SameSite=Strict.";
    } else if (!tokenFound && sameSiteHint === "Lax") {
      severity = "warn";
      note = "No CSRF token; SameSite=Lax mitigates most cross-site POSTs.";
    } else if (!tokenFound) {
      severity = "fail";
      note = "No CSRF token found and session cookie SameSite is None/Missing.";
    }

    forms.push({ endpoint, method, tokenFound, sameSiteHint, severity, note });
    if (forms.length >= 25) break;
  }

  if (forms.length === 0) {
    forms.push({
      endpoint: baseUrl.pathname,
      method: "POST",
      tokenFound: false,
      sameSiteHint,
      severity: "info" as Severity,
      note: "No state-changing HTML forms found on this page.",
    });
  }
  return forms;
}

// ---------- XSS (derived from CSP + encoding hints) ----------

function analyseXss(headers: HeaderRow[]): XssCase[] {
  const csp = headers.find((h) => h.name === "Content-Security-Policy");
  const xcto = headers.find((h) => h.name === "X-Content-Type-Options");
  const cspVal = csp?.value?.toLowerCase() ?? "";
  const cases: XssCase[] = [];

  cases.push({
    id: "XSS-CSP-PRESENCE",
    vector: "Content-Security-Policy",
    category: "CSP",
    severity: !csp?.value ? "fail" : "pass",
    detail: csp?.value
      ? "CSP is present and will constrain injected scripts."
      : "No CSP — reflected/stored XSS payloads can execute freely.",
  });

  cases.push({
    id: "XSS-CSP-UNSAFE-INLINE",
    vector: "script-src 'unsafe-inline'",
    category: "CSP",
    severity: cspVal.includes("'unsafe-inline'") ? "warn" : "pass",
    detail: cspVal.includes("'unsafe-inline'")
      ? "CSP allows 'unsafe-inline' — inline injected scripts run."
      : "'unsafe-inline' is not permitted for scripts.",
  });

  cases.push({
    id: "XSS-CSP-UNSAFE-EVAL",
    vector: "script-src 'unsafe-eval'",
    category: "CSP",
    severity: cspVal.includes("'unsafe-eval'") ? "warn" : "pass",
    detail: cspVal.includes("'unsafe-eval'")
      ? "eval() and similar are permitted; DOM XSS via string→code is possible."
      : "eval() is blocked by CSP.",
  });

  cases.push({
    id: "XSS-HEADER-NOSNIFF",
    vector: "X-Content-Type-Options: nosniff",
    category: "Headers",
    severity: xcto?.value?.toLowerCase().includes("nosniff") ? "pass" : "warn",
    detail: xcto?.value?.toLowerCase().includes("nosniff")
      ? "MIME-sniffing disabled; text uploaded as text won't execute as script."
      : "Missing nosniff — user-uploaded content may be sniffed as JavaScript.",
  });

  return cases;
}

// ---------- Sessions ----------

function analyseSessions(cookies: CookieRow[]): SessionCheck[] {
  const sessionCookies = cookies.filter((c) => /session|sid|auth|jwt|token/i.test(c.name));
  if (sessionCookies.length === 0) {
    return [
      { name: "Session cookie detected", status: "info", observation: "No obvious session cookie set by the initial response." },
    ];
  }
  return sessionCookies.flatMap<SessionCheck>((c) => [
    {
      name: `Session cookie \`${c.name}\` — HttpOnly`,
      status: c.httpOnly ? "pass" : "fail",
      observation: c.httpOnly ? "Not readable from JavaScript." : "Readable from JavaScript — XSS can steal the session.",
    },
    {
      name: `Session cookie \`${c.name}\` — Secure`,
      status: c.secure ? "pass" : "fail",
      observation: c.secure ? "Only sent over HTTPS." : "Sent over plain HTTP — network eavesdropping risk.",
    },
    {
      name: `Session cookie \`${c.name}\` — SameSite`,
      status: c.sameSite === "Strict" ? "pass" : c.sameSite === "Lax" ? "warn" : "fail",
      observation: `SameSite=${c.sameSite}. Strict is best for pure app-session cookies.`,
    },
  ]);
}

// ---------- Scoring ----------

function scoreRows(items: Array<{ severity: Severity }>): number {
  if (items.length === 0) return 100;
  let score = 100;
  for (const it of items) {
    if (it.severity === "fail") score -= 25;
    else if (it.severity === "warn") score -= 8;
  }
  return Math.max(0, Math.min(100, score));
}

// ---------- The scan itself ----------

async function performScan(rawUrl: string): Promise<Omit<ScanResult, "id" | "createdAt">> {
  const url = new URL(rawUrl);
  const start = Date.now();

  let response: Response;
  try {
    response = await fetch(url.toString(), {
      redirect: "manual",
      headers: {
        "User-Agent": "NSL-Scanner/1.0 (+https://novain-security-lab.dev)",
        Accept: "text/html,application/xhtml+xml",
      },
      signal: AbortSignal.timeout(15000),
    });
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    return {
      targetUrl: url.toString(),
      targetHost: url.host,
      status: "error",
      durationMs: Date.now() - start,
      overallScore: 0,
      scores: { headers: 0, cookies: 0, tls: 0, sessions: 0, csrf: 0, xss: 0 },
      headers: [],
      cookies: [],
      tls: {
        host: url.host, scheme: url.protocol === "https:" ? "https" : "http",
        hstsPresent: false, hstsPreloaded: false, hstsMaxAge: null, hstsIncludeSubDomains: false,
        issuer: null, validFrom: null, validTo: null, daysRemaining: null,
        severity: "fail", note: `Fetch failed: ${err}`,
      },
      csrf: [], xss: [], sessions: [],
      error: `Fetch failed: ${err}`,
    };
  }

  const headerRows = analyseHeaders(response.headers);
  const setCookies = (response.headers as unknown as { getSetCookie?: () => string[] })
    .getSetCookie?.() ?? [];
  const cookieRows = parseSetCookies(setCookies, url.host);
  let tls = analyseTls(url, response.headers);
  tls = await enrichTlsWithCert(tls);

  // Only read HTML for CSRF probing if likely HTML.
  const ct = response.headers.get("content-type") ?? "";
  let html = "";
  if (ct.includes("text/html") && response.status < 400) {
    try {
      html = (await response.text()).slice(0, 500_000);
    } catch { /* ignore */ }
  }
  const csrfRows = analyseCsrf(html, cookieRows, url);
  const xssRows = analyseXss(headerRows);
  const sessionRows = analyseSessions(cookieRows);

  const scores: ScoreBreakdown = {
    headers: scoreRows(headerRows),
    cookies: scoreRows(cookieRows),
    tls: tls.severity === "pass" ? 95 : tls.severity === "warn" ? 70 : 30,
    sessions: scoreRows(sessionRows.map((s) => ({ severity: s.status }))),
    csrf: scoreRows(csrfRows.filter((c) => c.severity !== "info")),
    xss: scoreRows(xssRows),
  };
  const overallScore = Math.round(
    (scores.headers + scores.cookies + scores.tls + scores.sessions + scores.csrf + scores.xss) / 6,
  );

  return {
    targetUrl: url.toString(),
    targetHost: url.host,
    status: "complete",
    durationMs: Date.now() - start,
    overallScore,
    scores,
    headers: headerRows,
    cookies: cookieRows,
    tls,
    csrf: csrfRows,
    xss: xssRows,
    sessions: sessionRows,
    error: null,
  };
}

export const runScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: { url: string }) => urlSchema.parse(data))
  .handler(async ({ data, context }): Promise<ScanResult> => {
    const scan = await performScan(data.url);
    const payload = {
      user_id: context.userId,
      target_url: scan.targetUrl,
      target_host: scan.targetHost,
      status: scan.status,
      duration_ms: scan.durationMs,
      overall_score: scan.overallScore,
      scores: scan.scores,
      headers: scan.headers,
      cookies: scan.cookies,
      tls: scan.tls,
      csrf: scan.csrf,
      xss: scan.xss,
      sessions: scan.sessions,
      error: scan.error,
    };
    const { data: row, error } = await context.supabase
      .from("scans")
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .insert(payload as any)
      .select("id, created_at")
      .single();
    if (error) throw new Error(error.message);
    return { ...scan, id: row.id as string, createdAt: row.created_at as string };
  });
