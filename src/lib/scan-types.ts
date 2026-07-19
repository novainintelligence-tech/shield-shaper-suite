import type { Severity } from "@/components/severity-badge";

export interface HeaderRow {
  name: string;
  value: string | null;
  expected: string;
  severity: Severity;
  note: string;
}

export interface CookieRow {
  name: string;
  domain: string;
  path: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Strict" | "Lax" | "None" | "Missing";
  expires: string;
  jsAccessible: boolean;
  severity: Severity;
}

export interface TlsResult {
  host: string;
  scheme: "https" | "http";
  hstsPresent: boolean;
  hstsPreloaded: boolean;
  hstsMaxAge: number | null;
  hstsIncludeSubDomains: boolean;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  severity: Severity;
  note: string;
}

export interface CsrfCheck {
  endpoint: string;
  method: "POST" | "PUT" | "DELETE" | "PATCH" | "GET";
  tokenFound: boolean;
  sameSiteHint: "Strict" | "Lax" | "None" | "Unknown";
  severity: Severity;
  note: string;
}

export interface XssCase {
  id: string;
  vector: string;
  category: "CSP" | "Encoding" | "Headers";
  severity: Severity;
  detail: string;
}

export interface SessionCheck {
  name: string;
  status: Severity;
  observation: string;
}

export interface ScoreBreakdown {
  headers: number;
  cookies: number;
  tls: number;
  sessions: number;
  csrf: number;
  xss: number;
}

export interface ScanResult {
  id: string;
  targetUrl: string;
  targetHost: string;
  status: "complete" | "error";
  durationMs: number | null;
  overallScore: number;
  scores: ScoreBreakdown;
  headers: HeaderRow[];
  cookies: CookieRow[];
  tls: TlsResult;
  csrf: CsrfCheck[];
  xss: XssCase[];
  sessions: SessionCheck[];
  error: string | null;
  createdAt: string;
}
