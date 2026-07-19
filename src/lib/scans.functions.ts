import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import type { ScanResult } from "./scan-types";

interface DbScanRow {
  id: string;
  target_url: string;
  target_host: string;
  status: string;
  duration_ms: number | null;
  overall_score: number;
  scores: ScanResult["scores"];
  headers: ScanResult["headers"];
  cookies: ScanResult["cookies"];
  tls: ScanResult["tls"];
  csrf: ScanResult["csrf"];
  xss: ScanResult["xss"];
  sessions: ScanResult["sessions"];
  error: string | null;
  created_at: string;
}

function toResult(row: DbScanRow): ScanResult {
  return {
    id: row.id,
    targetUrl: row.target_url,
    targetHost: row.target_host,
    status: row.status as "complete" | "error",
    durationMs: row.duration_ms,
    overallScore: row.overall_score,
    scores: row.scores,
    headers: row.headers,
    cookies: row.cookies,
    tls: row.tls,
    csrf: row.csrf,
    xss: row.xss,
    sessions: row.sessions,
    error: row.error,
    createdAt: row.created_at,
  };
}

export const getLatestScanForHost = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: { host: string }) => z.object({ host: z.string().min(1) }).parse(data))
  .handler(async ({ data, context }): Promise<ScanResult | null> => {
    const { data: rows, error } = await context.supabase
      .from("scans")
      .select("*")
      .eq("target_host", data.host)
      .order("created_at", { ascending: false })
      .limit(1);
    if (error) throw new Error(error.message);
    if (!rows || rows.length === 0) return null;
    return toResult(rows[0] as unknown as DbScanRow);
  });

export const listRecentScans = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }): Promise<ScanResult[]> => {
    const { data: rows, error } = await context.supabase
      .from("scans")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(50);
    if (error) throw new Error(error.message);
    return (rows ?? []).map((r) => toResult(r as unknown as DbScanRow));
  });

export const deleteScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: { id: string }) => z.object({ id: z.string().uuid() }).parse(data))
  .handler(async ({ data, context }) => {
    const { error } = await context.supabase.from("scans").delete().eq("id", data.id);
    if (error) throw new Error(error.message);
    return { ok: true };
  });
