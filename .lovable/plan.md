# Advanced Tools Suite

## User-facing outcome

Add an Advanced Tools workspace with four bounded, authorization-gated capabilities:

1. Fuzzer and parameter miner
2. Passive JavaScript and secrets scanner
3. WebSocket and GraphQL probe
4. JWT and token lab

Each tool supports server-side checks plus client-side browser capture/import where the browser is the only source of live session context. Results show timestamps, verdicts, exact request/response evidence, and remain available in run history.

## Implementation

### Backend and persistence

- Add an authenticated `advanced_tool_runs` table through a Lovable Cloud migration.
- Store owner, tool type, target, status, summary, findings, evidence, and timestamps.
- Grant only authenticated access, enable RLS, and scope reads/writes to the owner; editor/admin role checks control active runs.
- Add `src/lib/advanced-tools.functions.ts` with authenticated server functions for:
  - bounded parameter/path discovery with response-difference analysis;
  - passive same-origin JavaScript bundle discovery, source-map checks, endpoint extraction, and high-confidence secret-pattern detection without exfiltrating secret values;
  - WebSocket handshake/header/origin posture and GraphQL endpoint/introspection/batching-depth posture checks;
  - JWT decoding and defensive token metadata analysis, with no token persistence or private signing-key handling.
- Enforce HTTPS in production, same-origin target restrictions for discovered URLs, request/time budgets, and explicit authorization for active probes.

### UI and live browser context

- Create `src/routes/advanced-tools.tsx` with tabs for all four tools, target inputs, authorization controls, progress/results, raw evidence, and run history.
- Create `src/components/advanced-tool-result.tsx` for shared verdict and evidence rendering.
- Add client-only browser capture/import controls for the JS scanner and token lab using the existing live-session model; keep browser APIs behind event handlers/effect boundaries.
- Reuse `RawBlock`, `useMyRoles`, `useServerFn`, and the existing auth bearer middleware.
- Add the route to `src/components/app-sidebar.tsx`.

### Reporting integration

- Return a stable report-ready DTO from every run.
- Extend the existing JSON/SARIF and PDF export paths only where the current interfaces can accept the new run shape; do not duplicate export logic.

## Verification

- Regenerate database types after the migration.
- Run the strict TypeScript check.
- Verify the authenticated route renders, logged-out state is handled, and each tool returns a bounded result with raw evidence.
- Confirm no secrets, live browser tokens, or service credentials are persisted or returned in findings.

## Out of scope

- Credential attacks, brute-force authentication, destructive payloads, RCE, or unrestricted crawling.
- Reading cross-origin browser storage without the extension/bookmarklet capture path.
- Using Cloudflare Agents MCP APIs or adding an unrelated MCP integration.