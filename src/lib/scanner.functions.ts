import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import type {
  CookieRow,
  CsrfCheck,
  HeaderRow,
  ReconCheck,
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

const UA = "NSL-Scanner/1.1 (+https://novain-security-lab.dev)";

// ---------- Header analysis ----------

interface HeaderSpec {
  name: string;
  expected: string;
  evaluate: (value: string | null, all: Headers) => { severity: Severity; note: string };
}

const HEADER_SPECS: HeaderSpec[] = [
  {
    name: "Content-Security-Policy",
    expected: "Strict CSP without unsafe-inline / unsafe-eval / wildcards",
    evaluate: (v) => {
      if (!v) return { severity: "fail", note: "No CSP. Page can execute arbitrary inline/injected scripts." };
      const lower = v.toLowerCase();
      const bad: string[] = [];
      if (lower.includes("'unsafe-inline'")) bad.push("unsafe-inline");
      if (lower.includes("'unsafe-eval'")) bad.push("unsafe-eval");
      if (/(?:^|\s)\*(?:\s|;|$)/.test(lower)) bad.push("wildcard source");
      if (!/default-src|script-src/.test(lower)) bad.push("missing default-src/script-src");
      if (!/frame-ancestors/.test(lower)) bad.push("no frame-ancestors");
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
      if (maxAge < 15552000) return { severity: "warn", note: `max-age=${maxAge} is below the 6-month minimum.` };
      const missing: string[] = [];
      if (!/includesubdomains/i.test(v)) missing.push("includeSubDomains");
      if (!/preload/i.test(v)) missing.push("preload");
      if (missing.length) return { severity: "warn", note: `HSTS present but missing: ${missing.join(", ")}.` };
      return { severity: "pass", note: `HSTS enforced (max-age=${maxAge}, includeSubDomains, preload).` };
    },
  },
  {
    name: "X-Frame-Options",
    expected: "DENY or SAMEORIGIN (or CSP frame-ancestors)",
    evaluate: (v, all) => {
      const csp = (all.get("content-security-policy") ?? "").toLowerCase();
      if (!v && csp.includes("frame-ancestors"))
        return { severity: "pass", note: "Handled by CSP frame-ancestors." };
      if (!v) return { severity: "warn", note: "Missing. No clickjacking protection." };
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
      const good = /(no-referrer|strict-origin-when-cross-origin|same-origin)/i.test(v);
      return { severity: good ? "pass" : "warn", note: `Referrer-Policy: ${v}` };
    },
  },
  {
    name: "Permissions-Policy",
    expected: "Explicit deny for unused features",
    evaluate: (v) => {
      if (!v) return { severity: "warn", note: "Missing. Camera/microphone/geolocation implicitly allowed." };
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
  {
    name: "Cross-Origin-Opener-Policy",
    expected: "same-origin",
    evaluate: (v) => {
      if (!v) return { severity: "warn", note: "Missing. Popups can share browsing context with opener." };
      const good = /same-origin/i.test(v);
      return { severity: good ? "pass" : "warn", note: `COOP: ${v}` };
    },
  },
  {
    name: "Cross-Origin-Resource-Policy",
    expected: "same-site or same-origin",
    evaluate: (v) => {
      if (!v) return { severity: "warn", note: "Missing. Cross-origin sites may embed resources." };
      return { severity: "pass", note: `CORP: ${v}` };
    },
  },
  {
    name: "Cross-Origin-Embedder-Policy",
    expected: "require-corp (only if isolation needed)",
    evaluate: (v) => {
      if (!v) return { severity: "info", note: "COEP absent. Only required for cross-origin isolation." };
      return { severity: "pass", note: `COEP: ${v}` };
    },
  },
  {
    name: "Access-Control-Allow-Origin",
    expected: "Specific origin or absent (not '*' with credentials)",
    evaluate: (v, all) => {
      if (!v) return { severity: "pass", note: "No ACAO — API not exposed cross-origin by default." };
      const creds = (all.get("access-control-allow-credentials") ?? "").toLowerCase() === "true";
      if (v === "*" && creds) return { severity: "fail", note: "ACAO:* with credentials — invalid & dangerous intent." };
      if (v === "*") return { severity: "warn", note: "Wildcard ACAO — all responses exposed cross-origin." };
      return { severity: "pass", note: `ACAO scoped: ${v}` };
    },
  },
  {
    name: "Server",
    expected: "Absent or generic",
    evaluate: (v) => {
      if (!v) return { severity: "pass", note: "No Server header — no product/version leak." };
      if (/\d/.test(v)) return { severity: "warn", note: `Server version leak: "${v}".` };
      return { severity: "info", note: `Server header present: "${v}".` };
    },
  },
  {
    name: "X-Powered-By",
    expected: "Absent",
    evaluate: (v) => {
      if (!v) return { severity: "pass", note: "Not present." };
      return { severity: "warn", note: `Fingerprintable stack: "${v}".` };
    },
  },
];

function analyseHeaders(headers: Headers): HeaderRow[] {
  return HEADER_SPECS.map((spec) => {
    const value = headers.get(spec.name);
    const { severity, note } = spec.evaluate(value, headers);
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
    let domainExplicit = false;

    for (const attr of attrs) {
      const [k, v] = attr.split("=").map((s) => s?.trim());
      const key = k.toLowerCase();
      if (key === "httponly") httpOnly = true;
      else if (key === "secure") secure = true;
      else if (key === "samesite" && v) {
        const norm = v.charAt(0).toUpperCase() + v.slice(1).toLowerCase();
        if (norm === "Strict" || norm === "Lax" || norm === "None") sameSite = norm;
      } else if (key === "domain" && v) { domain = v; domainExplicit = true; }
      else if (key === "path" && v) path = v;
      else if (key === "max-age" && v) expires = `${v}s`;
      else if (key === "expires" && v) expires = v;
    }

    let severity: Severity = "pass";
    const notes: string[] = [];
    if (!secure || sameSite === "None") severity = "fail";
    else if (!httpOnly || sameSite === "Missing") severity = "warn";

    // Cookie prefix compliance (RFC 6265bis)
    if (name.startsWith("__Host-")) {
      if (!secure) { severity = "fail"; notes.push("__Host- prefix requires Secure."); }
      if (path !== "/") { severity = "fail"; notes.push("__Host- prefix requires Path=/."); }
      if (domainExplicit) { severity = "fail"; notes.push("__Host- prefix forbids Domain."); }
    } else if (name.startsWith("__Secure-") && !secure) {
      severity = "fail";
      notes.push("__Secure- prefix requires Secure.");
    }

    return {
      name, domain, path, httpOnly, secure, sameSite, expires,
      jsAccessible: !httpOnly, severity,
      note: notes.length ? notes.join(" ") : undefined,
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
  if (scheme === "http") { severity = "fail"; note = "Target is served over plain HTTP."; }
  else if (!hstsHeader) { severity = "warn"; note = "HTTPS in use, but no HSTS to prevent downgrade attacks."; }
  else if (!hstsMaxAge || hstsMaxAge < 15552000) { severity = "warn"; note = `HSTS present but max-age is only ${hstsMaxAge}s.`; }

  return {
    host: url.host, scheme,
    hstsPresent: !!hstsHeader, hstsPreloaded: preload, hstsMaxAge, hstsIncludeSubDomains: includeSub,
    issuer: null, validFrom: null, validTo: null, daysRemaining: null,
    severity, note,
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
    const rows = (await res.json()) as Array<{ issuer_name?: string; not_before?: string; not_after?: string }>;
    if (!Array.isArray(rows) || rows.length === 0) return tls;
    const now = Date.now();
    const active = rows
      .filter((r) => r.not_after && new Date(r.not_after).getTime() > now)
      .sort((a, b) => new Date(b.not_before!).getTime() - new Date(a.not_before!).getTime());
    const chosen = active[0] ?? rows[0];
    if (!chosen?.not_after) return tls;
    const daysRemaining = Math.round((new Date(chosen.not_after).getTime() - now) / (1000 * 60 * 60 * 24));
    let severity = tls.severity;
    let note = tls.note;
    if (daysRemaining < 14) { severity = "fail"; note = `Certificate expires in ${daysRemaining} days.`; }
    else if (daysRemaining < 30 && severity === "pass") { severity = "warn"; note = `Certificate expires in ${daysRemaining} days.`; }
    return {
      ...tls,
      issuer: chosen.issuer_name?.split(",").find((p) => p.trim().startsWith("O="))?.replace(/^\s*O=/, "") ?? chosen.issuer_name ?? null,
      validFrom: chosen.not_before ?? null,
      validTo: chosen.not_after ?? null,
      daysRemaining, severity, note,
    };
  } catch { return tls; }
}

// ---------- CSRF ----------

function analyseCsrf(html: string, cookies: CookieRow[], baseUrl: URL): CsrfCheck[] {
  const forms: CsrfCheck[] = [];
  const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let match: RegExpExecArray | null;
  const sessionCookie = cookies.find((c) => /session|sid|auth|jwt|token/i.test(c.name));
  const sameSiteHint: CsrfCheck["sameSiteHint"] = sessionCookie
    ? (sessionCookie.sameSite === "Missing" ? "Unknown" : sessionCookie.sameSite)
    : "Unknown";

  const metaTokenPresent = /<meta[^>]+name\s*=\s*["'](csrf-token|csrf_token|_csrf|_token|xsrf-token)["'][^>]*>/i.test(html);

  while ((match = formRegex.exec(html)) !== null) {
    const attrs = match[1];
    const body = match[2];
    const methodMatch = /method\s*=\s*["']?(\w+)/i.exec(attrs);
    const method = (methodMatch?.[1]?.toUpperCase() ?? "GET") as CsrfCheck["method"];
    const actionMatch = /action\s*=\s*["']([^"']*)/i.exec(attrs);
    const action = actionMatch?.[1] ?? "";
    let endpoint = action || baseUrl.pathname;
    try { endpoint = new URL(action || baseUrl.pathname, baseUrl).pathname; } catch { /* ignore */ }
    if (method === "GET") continue;

    const tokenFound =
      /<input[^>]+(name|id)\s*=\s*["'][^"']*(csrf|xsrf|token|authenticity|requestverification|nonce)[^"']*["']/i.test(body)
      || metaTokenPresent;

    let severity: Severity = "pass";
    let note = tokenFound ? "CSRF token detected (form field or meta)." : "No CSRF token located.";
    if (!tokenFound && sameSiteHint === "Strict") { severity = "warn"; note = "No token, but session cookie is SameSite=Strict."; }
    else if (!tokenFound && sameSiteHint === "Lax") { severity = "warn"; note = "No token; SameSite=Lax mitigates most cross-site POSTs but not top-level GET→POST."; }
    else if (!tokenFound) { severity = "fail"; note = "No CSRF token and session cookie SameSite is None/Missing."; }

    forms.push({ endpoint, method, tokenFound, sameSiteHint, severity, note });
    if (forms.length >= 25) break;
  }

  if (forms.length === 0) {
    forms.push({
      endpoint: baseUrl.pathname, method: "POST", tokenFound: false, sameSiteHint,
      severity: "info" as Severity,
      note: "No state-changing HTML forms found on this page.",
    });
  }
  return forms;
}

// ---------- XSS ----------

function analyseXss(headers: HeaderRow[]): XssCase[] {
  const csp = headers.find((h) => h.name === "Content-Security-Policy");
  const xcto = headers.find((h) => h.name === "X-Content-Type-Options");
  const cspVal = csp?.value?.toLowerCase() ?? "";
  const cases: XssCase[] = [];

  cases.push({
    id: "XSS-CSP-PRESENCE", vector: "Content-Security-Policy", category: "CSP",
    severity: !csp?.value ? "fail" : "pass",
    detail: csp?.value ? "CSP present — constrains injected scripts." : "No CSP — reflected/stored XSS payloads can execute freely.",
  });
  cases.push({
    id: "XSS-CSP-UNSAFE-INLINE", vector: "script-src 'unsafe-inline'", category: "CSP",
    severity: cspVal.includes("'unsafe-inline'") ? "warn" : "pass",
    detail: cspVal.includes("'unsafe-inline'") ? "CSP allows 'unsafe-inline' — inline injected scripts run." : "'unsafe-inline' not permitted.",
  });
  cases.push({
    id: "XSS-CSP-UNSAFE-EVAL", vector: "script-src 'unsafe-eval'", category: "CSP",
    severity: cspVal.includes("'unsafe-eval'") ? "warn" : "pass",
    detail: cspVal.includes("'unsafe-eval'") ? "eval() permitted — DOM XSS via string→code is possible." : "eval() blocked.",
  });
  cases.push({
    id: "XSS-HEADER-NOSNIFF", vector: "X-Content-Type-Options: nosniff", category: "Headers",
    severity: xcto?.value?.toLowerCase().includes("nosniff") ? "pass" : "warn",
    detail: xcto?.value?.toLowerCase().includes("nosniff") ? "MIME-sniffing disabled." : "Missing nosniff — user uploads may sniff as JS.",
  });
  return cases;
}

async function probeReflectedXss(url: URL): Promise<XssCase[]> {
  const canary = `nsl${Math.random().toString(36).slice(2, 10)}zz`;
  const probeUrl = new URL(url.toString());
  probeUrl.searchParams.set("nsl_probe", `<script>${canary}</script>`);
  try {
    const res = await fetch(probeUrl.toString(), {
      redirect: "follow",
      headers: { "User-Agent": UA, Accept: "text/html" },
      signal: AbortSignal.timeout(10000),
    });
    const ct = res.headers.get("content-type") ?? "";
    if (!ct.includes("text/html")) return [];
    const body = (await res.text()).slice(0, 500_000);
    const raw = body.includes(`<script>${canary}</script>`);
    const encoded = body.includes(`&lt;script&gt;${canary}&lt;/script&gt;`) || body.includes(canary);
    if (raw) return [{ id: "XSS-REFLECT-RAW", vector: "?nsl_probe=<script>…</script>", category: "Reflected", severity: "fail", detail: "Payload reflected verbatim — reflected XSS sink." }];
    if (encoded) return [{ id: "XSS-REFLECT-ENC", vector: "?nsl_probe=<script>…</script>", category: "Reflected", severity: "pass", detail: "Payload reflected but HTML-escaped." }];
    return [{ id: "XSS-REFLECT-NONE", vector: "?nsl_probe=<script>…</script>", category: "Reflected", severity: "pass", detail: "Payload not reflected." }];
  } catch { return []; }
}

async function probeCors(url: URL): Promise<XssCase[]> {
  const attacker = "https://nsl-scanner.example";
  try {
    const res = await fetch(url.toString(), {
      method: "GET", redirect: "manual",
      headers: { Origin: attacker, "User-Agent": UA },
      signal: AbortSignal.timeout(8000),
    });
    const acao = res.headers.get("access-control-allow-origin") ?? "";
    const acac = (res.headers.get("access-control-allow-credentials") ?? "").toLowerCase() === "true";
    if (!acao) return [{ id: "XSS-CORS-OK", vector: "Origin reflection probe", category: "CORS", severity: "pass", detail: "No CORS headers exposed to arbitrary origins." }];
    if (acao === attacker && acac) return [{ id: "XSS-CORS-REFLECT", vector: "ACAO reflects Origin + credentials", category: "CORS", severity: "fail", detail: `Origin ${attacker} reflected with credentials — full CORS bypass.` }];
    if (acao === attacker) return [{ id: "XSS-CORS-REFLECT-NC", vector: "ACAO reflects Origin", category: "CORS", severity: "warn", detail: "Arbitrary origin reflected (no credentials). Responses readable cross-origin." }];
    if (acao === "*" && acac) return [{ id: "XSS-CORS-CRIT", vector: "ACAO:* + credentials", category: "CORS", severity: "fail", detail: "Dangerous CORS intent (browser blocks but signals misconfig)." }];
    if (acao === "*") return [{ id: "XSS-CORS-WILD", vector: "ACAO:*", category: "CORS", severity: "warn", detail: "Wildcard CORS — safe without credentials but exposes all responses." }];
    return [{ id: "XSS-CORS-SCOPED", vector: `ACAO: ${acao}`, category: "CORS", severity: "pass", detail: "CORS scoped to a specific origin." }];
  } catch { return []; }
}

// ---------- Sessions ----------

function analyseSessions(cookies: CookieRow[]): SessionCheck[] {
  const sessionCookies = cookies.filter((c) => /session|sid|auth|jwt|token/i.test(c.name));
  if (sessionCookies.length === 0) {
    return [{ name: "Session cookie detected", status: "info", observation: "No obvious session cookie set by the initial response." }];
  }
  return sessionCookies.flatMap<SessionCheck>((c) => [
    { name: `\`${c.name}\` — HttpOnly`, status: c.httpOnly ? "pass" : "fail",
      observation: c.httpOnly ? "Not readable from JavaScript." : "Readable from JavaScript — XSS can steal the session." },
    { name: `\`${c.name}\` — Secure`, status: c.secure ? "pass" : "fail",
      observation: c.secure ? "Only sent over HTTPS." : "Sent over plain HTTP — eavesdropping risk." },
    { name: `\`${c.name}\` — SameSite`, status: c.sameSite === "Strict" ? "pass" : c.sameSite === "Lax" ? "warn" : "fail",
      observation: `SameSite=${c.sameSite}. Strict is best for pure app-session cookies.` },
    { name: `\`${c.name}\` — Prefix`,
      status: c.name.startsWith("__Host-") ? "pass" : c.name.startsWith("__Secure-") ? "warn" : "info",
      observation: c.name.startsWith("__Host-")
        ? "__Host- prefix in use — strongest binding to origin."
        : c.name.startsWith("__Secure-")
          ? "__Secure- prefix in use — consider upgrading to __Host-."
          : "No cookie prefix — consider __Host-/__Secure- for defense-in-depth." },
  ]);
}

// ---------- Recon probes ----------

const EXPOSURE_PATHS: Array<{ p: string; name: string; critical: boolean }> = [
  { p: "/.env", name: ".env file", critical: true },
  { p: "/.git/HEAD", name: ".git/HEAD", critical: true },
  { p: "/.git/config", name: ".git/config", critical: true },
  { p: "/server-status", name: "Apache server-status", critical: true },
  { p: "/phpinfo.php", name: "phpinfo()", critical: true },
  { p: "/wp-login.php", name: "WordPress login", critical: false },
  { p: "/admin", name: "/admin path", critical: false },
  { p: "/actuator", name: "Spring actuator", critical: true },
];

async function probeExposure(base: URL): Promise<ReconCheck[]> {
  return Promise.all(EXPOSURE_PATHS.map(async ({ p, name, critical }) => {
    try {
      const u = new URL(p, `${base.origin}/`);
      const res = await fetch(u.toString(), {
        method: "GET", redirect: "manual",
        headers: { "User-Agent": UA, Range: "bytes=0-256" },
        signal: AbortSignal.timeout(6000),
      });
      if (res.status === 200 || res.status === 206) {
        return { id: `EXP:${p}`, category: "exposure" as const, name,
          severity: (critical ? "fail" : "warn") as Severity,
          note: `HTTP ${res.status} — endpoint served content. Verify it does not leak secrets or admin functionality.`,
          target: p };
      }
      if (res.status === 401 || res.status === 403) {
        return { id: `EXP:${p}`, category: "exposure" as const, name,
          severity: "info" as Severity,
          note: `HTTP ${res.status} — endpoint exists but is access-controlled.`, target: p };
      }
      return { id: `EXP:${p}`, category: "exposure" as const, name,
        severity: "pass" as Severity, note: `HTTP ${res.status} — not exposed.`, target: p };
    } catch {
      return { id: `EXP:${p}`, category: "exposure" as const, name,
        severity: "pass" as Severity, note: "Request failed / timed out.", target: p };
    }
  }));
}

async function probeMeta(base: URL): Promise<ReconCheck[]> {
  const checks: Array<{ p: string; name: string; missingSev: Severity; missingNote: string }> = [
    { p: "/.well-known/security.txt", name: "security.txt", missingSev: "warn", missingNote: "No security.txt — vulnerability reporting channel is not published." },
    { p: "/robots.txt", name: "robots.txt", missingSev: "info", missingNote: "No robots.txt served." },
    { p: "/sitemap.xml", name: "sitemap.xml", missingSev: "info", missingNote: "No sitemap.xml served." },
  ];
  return Promise.all(checks.map(async ({ p, name, missingSev, missingNote }) => {
    try {
      const u = new URL(p, `${base.origin}/`);
      const res = await fetch(u.toString(), {
        method: "GET", redirect: "manual",
        headers: { "User-Agent": UA }, signal: AbortSignal.timeout(6000),
      });
      if (res.status === 200) {
        return { id: `META:${p}`, category: "meta" as const, name,
          severity: "pass" as Severity, note: `HTTP 200 — ${name} present.`, target: p };
      }
      return { id: `META:${p}`, category: "meta" as const, name, severity: missingSev, note: missingNote, target: p };
    } catch {
      return { id: `META:${p}`, category: "meta" as const, name, severity: "info" as Severity, note: "Probe failed.", target: p };
    }
  }));
}

function analyseMixedContent(html: string, base: URL): ReconCheck[] {
  if (base.protocol !== "https:") return [];
  const httpRefs = (html.match(/(?:src|href)\s*=\s*["']http:\/\/[^"']+/gi) ?? []).slice(0, 20);
  if (httpRefs.length === 0) {
    return [{ id: "MIX:none", category: "mixed-content", name: "Mixed content", severity: "pass", note: "No http:// subresources found in initial HTML." }];
  }
  return [{ id: "MIX:found", category: "mixed-content", name: "Mixed content", severity: "fail",
    note: `${httpRefs.length} http:// subresource references on an HTTPS page. Example: ${httpRefs[0].slice(0, 120)}` }];
}

async function probeRedirect(base: URL): Promise<ReconCheck[]> {
  if (base.protocol !== "https:") {
    return [{ id: "RED:http", category: "redirect", name: "HTTPS enforcement", severity: "fail",
      note: "Target is served over http:// — no TLS enforcement." }];
  }
  const httpUrl = `http://${base.host}${base.pathname}`;
  try {
    const res = await fetch(httpUrl, {
      method: "HEAD", redirect: "manual",
      headers: { "User-Agent": UA }, signal: AbortSignal.timeout(6000),
    });
    const loc = res.headers.get("location") ?? "";
    if (res.status >= 300 && res.status < 400 && loc.startsWith("https://")) {
      return [{ id: "RED:https", category: "redirect", name: "HTTP → HTTPS redirect", severity: "pass", note: `HTTP ${res.status} → ${loc}` }];
    }
    if (res.status >= 200 && res.status < 300) {
      return [{ id: "RED:plain", category: "redirect", name: "Plain HTTP accepted", severity: "fail",
        note: `HTTP ${res.status} on http:// — plaintext content served without upgrade.` }];
    }
    return [{ id: "RED:other", category: "redirect", name: "HTTP endpoint response", severity: "info", note: `HTTP ${res.status} on http:// endpoint.` }];
  } catch {
    return [{ id: "RED:closed", category: "redirect", name: "HTTP endpoint", severity: "pass", note: "http:// port not reachable — TLS-only." }];
  }
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

// ---------- Full scan ----------

async function performScan(rawUrl: string): Promise<Omit<ScanResult, "id" | "createdAt">> {
  const url = new URL(rawUrl);
  const start = Date.now();

  let response: Response;
  try {
    response = await fetch(url.toString(), {
      redirect: "manual",
      headers: { "User-Agent": UA, Accept: "text/html,application/xhtml+xml" },
      signal: AbortSignal.timeout(15000),
    });
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    return {
      targetUrl: url.toString(), targetHost: url.host, status: "error",
      durationMs: Date.now() - start, overallScore: 0,
      scores: { headers: 0, cookies: 0, tls: 0, sessions: 0, csrf: 0, xss: 0, recon: 0 },
      headers: [], cookies: [],
      tls: {
        host: url.host, scheme: url.protocol === "https:" ? "https" : "http",
        hstsPresent: false, hstsPreloaded: false, hstsMaxAge: null, hstsIncludeSubDomains: false,
        issuer: null, validFrom: null, validTo: null, daysRemaining: null,
        severity: "fail", note: `Fetch failed: ${err}`,
      },
      csrf: [], xss: [], sessions: [], recon: [],
      error: `Fetch failed: ${err}`,
    };
  }

  const headerRows = analyseHeaders(response.headers);
  const setCookies = (response.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
  const cookieRows = parseSetCookies(setCookies, url.host);
  let tls = analyseTls(url, response.headers);

  const ct = response.headers.get("content-type") ?? "";
  let html = "";
  if (ct.includes("text/html") && response.status < 400) {
    try { html = (await response.text()).slice(0, 500_000); } catch { /* ignore */ }
  }

  // Run all deep probes in parallel
  const [certTls, reflected, cors, exposure, meta, redirect] = await Promise.all([
    enrichTlsWithCert(tls),
    probeReflectedXss(url),
    probeCors(url),
    probeExposure(url),
    probeMeta(url),
    probeRedirect(url),
  ]);
  tls = certTls;

  const csrfRows = analyseCsrf(html, cookieRows, url);
  const xssRows = [...analyseXss(headerRows), ...reflected, ...cors];
  const sessionRows = analyseSessions(cookieRows);
  const reconRows: ReconCheck[] = [
    ...exposure,
    ...meta,
    ...analyseMixedContent(html, url),
    ...redirect,
  ];

  const scores: ScoreBreakdown = {
    headers: scoreRows(headerRows),
    cookies: scoreRows(cookieRows),
    tls: tls.severity === "pass" ? 95 : tls.severity === "warn" ? 70 : 30,
    sessions: scoreRows(sessionRows.map((s) => ({ severity: s.status }))),
    csrf: scoreRows(csrfRows.filter((c) => c.severity !== "info")),
    xss: scoreRows(xssRows),
    recon: scoreRows(reconRows.filter((r) => r.severity !== "info")),
  };
  const overallScore = Math.round(
    (scores.headers + scores.cookies + scores.tls + scores.sessions + scores.csrf + scores.xss + scores.recon) / 7,
  );

  return {
    targetUrl: url.toString(), targetHost: url.host, status: "complete",
    durationMs: Date.now() - start, overallScore, scores,
    headers: headerRows, cookies: cookieRows, tls,
    csrf: csrfRows, xss: xssRows, sessions: sessionRows, recon: reconRows,
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
      recon: scan.recon,
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
