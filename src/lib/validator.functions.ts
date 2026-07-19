import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { probeStep, type ProbeStep } from "@/lib/http-probe.server";

export type Verdict = "confirmed" | "not-exploitable" | "inconclusive" | "skipped" | "error";

export interface ValidationResult {
  findingId: string;
  ranAt: string;
  verdict: Verdict;
  summary: string;
  poc: string;
  active: boolean;
  steps: ProbeStep[];
}

const InputSchema = z.object({
  findingId: z.string().min(1).max(200),
  targetUrl: z.string().url(),
  path: z.string().max(500).optional(),
  authorizeActive: z.boolean().optional().default(false),
}).refine((v) => v.targetUrl.startsWith("https://"), "targetUrl must be https://");

function hostOf(u: string): string {
  try { return new URL(u).host; } catch { return ""; }
}

function assertSameHost(base: string, other: string): void {
  if (hostOf(base) !== hostOf(other)) {
    throw new Error(`PoC target host ${hostOf(other)} does not match scan host ${hostOf(base)}.`);
  }
}

// ---------- individual PoCs ----------

async function pocHsts(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const httpUrl = target.replace(/^https:\/\//, "http://");
  const s1 = await probeStep("Force http:// request", "GET", httpUrl);
  const steps = [s1];
  let verdict: Verdict = "inconclusive";
  let summary = "";
  const loc = s1.responseHeaders["location"] ?? "";
  const hstsOnRedirect = s1.responseHeaders["strict-transport-security"];
  if (s1.status && s1.status >= 300 && s1.status < 400 && loc.startsWith("https://")) {
    if (hstsOnRedirect) {
      verdict = "not-exploitable";
      summary = `Server issued ${s1.status} → ${loc} with HSTS present. Downgrade is blocked on subsequent visits.`;
    } else {
      verdict = "confirmed";
      summary = `Server redirects to HTTPS (${s1.status}) but the http:// response does NOT set HSTS. First-visit downgrade window is exploitable.`;
    }
  } else if (s1.status && s1.status >= 200 && s1.status < 300) {
    verdict = "confirmed";
    summary = `Server answered ${s1.status} over plain http:// — traffic can be intercepted.`;
  } else if (!s1.status) {
    verdict = "not-exploitable";
    summary = `http:// endpoint refused connection (${s1.error ?? "no response"}).`;
  } else {
    verdict = "inconclusive";
    summary = `http:// returned ${s1.status}. Manual review required.`;
  }
  return {
    verdict,
    summary,
    poc: "Downgrade probe: request the same URL over http:// and inspect the response.",
    steps,
  };
}

async function pocHeader(target: string, headerName: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const s1 = await probeStep(`Refetch to inspect ${headerName}`, "GET", target);
  const value = s1.responseHeaders[headerName.toLowerCase()];
  let verdict: Verdict = "inconclusive";
  let summary = "";
  if (!value) {
    verdict = "confirmed";
    summary = `${headerName} is absent from the live response — browser protection unavailable.`;
    if (headerName === "X-Frame-Options") {
      const csp = s1.responseHeaders["content-security-policy"] ?? "";
      if (/frame-ancestors/i.test(csp)) {
        verdict = "not-exploitable";
        summary = `${headerName} absent, but CSP frame-ancestors present: ${csp.match(/frame-ancestors[^;]*/i)?.[0]}`;
      } else {
        summary += " No CSP frame-ancestors fallback either — target is clickjackable.";
      }
    }
  } else {
    verdict = "not-exploitable";
    summary = `${headerName} is present: ${value}`;
  }
  return {
    verdict,
    summary,
    poc: `GET the target and read the ${headerName} response header.`,
    steps: [s1],
  };
}

async function pocCookie(target: string, cookieName: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const s1 = await probeStep("Refetch to inspect Set-Cookie", "GET", target);
  const line = s1.setCookies.find((c) => c.split(";")[0].split("=")[0].trim() === cookieName);
  let verdict: Verdict = "inconclusive";
  let summary = "";
  if (!line) {
    verdict = "inconclusive";
    summary = `Cookie "${cookieName}" was not re-issued on this request. It may only be set after login or on specific paths.`;
  } else {
    const flags = line.toLowerCase();
    const missing: string[] = [];
    if (!flags.includes("httponly")) missing.push("HttpOnly");
    if (!flags.includes("secure")) missing.push("Secure");
    if (!/samesite=/.test(flags)) missing.push("SameSite");
    if (missing.length === 0) {
      verdict = "not-exploitable";
      summary = `Cookie "${cookieName}" carries HttpOnly, Secure, and SameSite. Not exploitable by client-side theft.`;
    } else {
      verdict = "confirmed";
      summary = `Cookie "${cookieName}" is missing: ${missing.join(", ")}. Raw line captured below.`;
    }
  }
  return {
    verdict,
    summary,
    poc: "Refetch target, isolate the Set-Cookie line for this cookie, and enumerate missing flags.",
    steps: [s1],
  };
}

async function pocXss(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const canary = `nsl${Math.random().toString(36).slice(2, 10)}`;
  const payload = `"><svg/onload=${canary}>`;
  const u = new URL(target);
  u.searchParams.set("q", payload);
  const s1 = await probeStep("Inject canary payload via ?q=", "GET", u.toString());
  const body = s1.bodySnippet;
  let verdict: Verdict = "inconclusive";
  let summary = "";
  if (!body.includes(canary) && !body.includes(payload)) {
    verdict = "not-exploitable";
    summary = "Canary was not reflected in the response body.";
  } else {
    const idx = body.indexOf(canary) >= 0 ? body.indexOf(canary) : body.indexOf(payload);
    const window = body.slice(Math.max(0, idx - 60), Math.min(body.length, idx + 80));
    const encoded = /&lt;|&#x3c;|&#60;/i.test(window);
    if (encoded) {
      verdict = "not-exploitable";
      summary = `Reflection observed but HTML-encoded — escape appears intact. Context: …${window}…`;
    } else if (/<svg[^>]*onload/i.test(window)) {
      verdict = "confirmed";
      summary = `Payload reflected raw inside HTML context — executable in a browser. Context: …${window}…`;
    } else {
      verdict = "inconclusive";
      summary = `Reflection observed but escape context ambiguous. Context: …${window}…`;
    }
  }
  return {
    verdict,
    summary,
    poc: `Inject a benign canary ("${payload}") into ?q= and locate reflection context.`,
    steps: [s1],
  };
}

async function pocExposure(target: string, path: string | undefined): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const p = path && path.startsWith("/") ? path : `/${path ?? ""}`;
  const url = new URL(p, target).toString();
  assertSameHost(target, url);
  const s1 = await probeStep(`Fetch exposed path ${p}`, "GET", url);
  let verdict: Verdict = "inconclusive";
  let summary = "";
  if (s1.status && s1.status >= 200 && s1.status < 300 && s1.bodyBytes > 0) {
    verdict = "confirmed";
    summary = `${p} returned ${s1.status} with ${s1.bodyBytes} bytes. First bytes below prove exposure.`;
  } else if (s1.status && (s1.status === 401 || s1.status === 403)) {
    verdict = "not-exploitable";
    summary = `${p} returned ${s1.status} — access controls in place.`;
  } else if (s1.status && s1.status === 404) {
    verdict = "not-exploitable";
    summary = `${p} returned 404 — resource no longer present.`;
  } else {
    verdict = "inconclusive";
    summary = `${p} returned ${s1.status ?? s1.error ?? "no response"}.`;
  }
  return {
    verdict,
    summary,
    poc: `Unauthenticated GET against the exposed path.`,
    steps: [s1],
  };
}

async function pocRedirect(target: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const steps: ProbeStep[] = [];
  const origin = new URL(target).origin;
  let current = target;
  let verdict: Verdict = "not-exploitable";
  let summary = "No off-origin or protocol-downgrading redirect observed within 5 hops.";
  for (let i = 0; i < 5; i++) {
    const s = await probeStep(`Hop ${i + 1}`, "GET", current);
    steps.push(s);
    if (!s.status || s.status < 300 || s.status >= 400) break;
    const loc = s.responseHeaders["location"];
    if (!loc) break;
    const next = new URL(loc, current).toString();
    if (new URL(next).origin !== origin) {
      verdict = "confirmed";
      summary = `Redirect leaves origin: ${current} → ${next}.`;
      break;
    }
    if (next.startsWith("http://")) {
      verdict = "confirmed";
      summary = `Redirect downgrades scheme: ${current} → ${next}.`;
      break;
    }
    current = next;
  }
  return {
    verdict,
    summary,
    poc: "Follow the redirect chain up to 5 hops; flag off-origin or protocol downgrade.",
    steps,
  };
}

async function pocCsrfActive(target: string, endpoint: string): Promise<Omit<ValidationResult, "findingId" | "ranAt" | "active">> {
  const url = endpoint.startsWith("http") ? endpoint : new URL(endpoint, target).toString();
  assertSameHost(target, url);
  const s1 = await probeStep("Cross-origin POST (no cookies, forged Origin)", "POST", url, {
    body: "",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "origin": "https://nsl-poc.invalid",
      "referer": "https://nsl-poc.invalid/",
    },
  });
  let verdict: Verdict = "inconclusive";
  let summary = "";
  if (s1.status && s1.status >= 200 && s1.status < 300) {
    verdict = "confirmed";
    summary = `Endpoint accepted cross-origin POST with forged Origin header (status ${s1.status}). CSRF surface is real.`;
  } else if (s1.status === 401 || s1.status === 403) {
    verdict = "not-exploitable";
    summary = `Endpoint rejected the cross-origin request with ${s1.status}.`;
  } else if (s1.status && s1.status >= 300 && s1.status < 400) {
    const loc = (s1.responseHeaders["location"] ?? "").toLowerCase();
    verdict = /login|sign[-_ ]?in|auth/.test(loc) ? "not-exploitable" : "inconclusive";
    summary = `Redirected ${s1.status} → ${loc || "(no Location)"}.`;
  } else {
    verdict = "inconclusive";
    summary = `Server returned ${s1.status ?? s1.error ?? "no response"}.`;
  }
  return {
    verdict,
    summary,
    poc: "POST to the endpoint from an off-origin caller with no session cookies and a forged Origin header.",
    steps: [s1],
  };
}

// ---------- dispatcher ----------

export const runValidation = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: z.infer<typeof InputSchema>) => InputSchema.parse(data))
  .handler(async ({ data }): Promise<ValidationResult> => {
    const id = data.findingId;
    const ranAt = new Date().toISOString();

    const wrap = (
      active: boolean,
      body: Omit<ValidationResult, "findingId" | "ranAt" | "active">,
    ): ValidationResult => ({ findingId: id, ranAt, active, ...body });

    try {
      // ---- HSTS ----
      if (id === "hdr-Strict-Transport-Security") {
        return wrap(false, await pocHsts(data.targetUrl));
      }
      // ---- headers ----
      if (id.startsWith("hdr-")) {
        const name = id.slice(4);
        return wrap(false, await pocHeader(data.targetUrl, name));
      }
      // ---- cookies ----
      if (id.startsWith("cookie-")) {
        const name = id.slice(7);
        return wrap(false, await pocCookie(data.targetUrl, name));
      }
      // ---- TLS posture ----
      if (id === "tls-posture") {
        return wrap(false, await pocHsts(data.targetUrl));
      }
      // ---- XSS ----
      if (id.startsWith("xss-")) {
        return wrap(false, await pocXss(data.targetUrl));
      }
      // ---- Recon exposure / redirect ----
      if (id.startsWith("recon-")) {
        if (id.includes("redirect") || id.startsWith("recon-redirect")) {
          return wrap(false, await pocRedirect(data.targetUrl));
        }
        return wrap(false, await pocExposure(data.targetUrl, data.path));
      }
      // ---- CSRF (ACTIVE) ----
      if (id.startsWith("csrf-")) {
        if (!data.authorizeActive) {
          return wrap(true, {
            verdict: "skipped",
            summary: "Active PoC blocked. Toggle 'I authorize active exploitation on this target I own' to run.",
            poc: "Cross-origin POST from an untrusted origin.",
            steps: [],
          });
        }
        const endpoint = data.path ?? id.slice(5);
        return wrap(true, await pocCsrfActive(data.targetUrl, endpoint));
      }
      // ---- Session (needs reauth probe) ----
      if (id.startsWith("session-")) {
        return wrap(false, {
          verdict: "inconclusive",
          summary: "Session-handling findings require credentials. Run the Reauth Probe module to validate.",
          poc: "See /reauth for authenticated session validation.",
          steps: [],
        });
      }

      return wrap(false, {
        verdict: "inconclusive",
        summary: `No automated PoC available for finding id "${id}".`,
        poc: "Manual verification required.",
        steps: [],
      });
    } catch (e) {
      return wrap(false, {
        verdict: "error",
        summary: e instanceof Error ? e.message : String(e),
        poc: "",
        steps: [],
      });
    }
  });
