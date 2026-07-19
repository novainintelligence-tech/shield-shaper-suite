# Vulnerability Validator — Proof-of-Concept engine

Turns each finding produced by `buildFindings()` into an executable proof:
NSL re-issues the exact HTTP request(s) needed to demonstrate the finding,
captures the raw request/response, and returns a verdict of
**Confirmed / Not exploitable / Inconclusive** with the evidence attached.

## What gets built

### 1. `src/lib/validator.functions.ts` (new)
A single authenticated `createServerFn`, `runValidation`, that dispatches
on the finding id prefix produced by `engagement.ts`. Every branch
returns the same `ValidationResult` shape: `verdict`, `summary`, and an
array of `steps` (request/response pairs with headers + body snippet)
so the UI can render them exactly like the reauth probe.

Dispatch table (all keyed off ids already emitted by `buildFindings`):

| Finding id prefix | Category | PoC performed | Gate |
|---|---|---|---|
| `hdr-Strict-Transport-Security` | Safe | Fetch `http://<host>`, verify 301→https + HSTS on the redirected response | — |
| `hdr-X-Frame-Options`, `hdr-Content-Security-Policy` (frame-ancestors) | Safe | Refetch, dump the exact header (or absence), classify clickjackable | — |
| `hdr-*` (other) | Safe | Refetch, echo raw header + expected | — |
| `cookie-*` | Safe | Refetch target, isolate the exact `Set-Cookie` line, mark which flag is missing, prove `document.cookie` visibility for non-HttpOnly | — |
| `tls-posture` | Safe | Attempt `http://` fetch, record downgrade behavior + HSTS response | — |
| `csrf-*` | **Active** | Cross-origin `POST` with `Origin: https://nsl-poc.invalid` and no cookies; verdict = Confirmed only if the endpoint accepts (2xx and not a login redirect). Never uses captured session cookies. | ✅ authorize |
| `xss-*` | Safe | Re-inject scan canary via query param, locate reflection context (attribute / text / script), classify escape | — |
| `recon-*` (exposure) | Safe | Refetch the exposed path, verdict = Confirmed if 2xx and body length > 0, include first 2 KB | — |
| `recon-*` (redirect) | Safe | Follow chain up to 5 hops, verdict on off-host or protocol-downgrade | — |
| `session-*` | Inconclusive by design | Points user to the Reauth Probe (needs credentials); returns explanatory verdict | — |

Rules of engagement enforced in the handler:
- Every URL must be https and resolve to the host of the scan being
  validated (rejects arbitrary URLs).
- Total request budget per call: 8 requests, 15 s wall clock.
- `authorizeActive: true` is required for any 🔴 Active row; otherwise
  returns `verdict: "skipped"` with a reason.
- No user credentials, no cookies from the browser session, no writes
  to the database.

### 2. `src/routes/validator.tsx` (new)
Batch view listing every finding from the latest scan (reuses
`buildFindings`). Columns: severity, module, title, PoC type
(Safe/Active), action button. Header controls:
- "Run all safe PoCs" — sequential, updates each row as it finishes
- Global "I authorize active exploitation on this target I own" checkbox
  that unlocks Active row buttons
- Per-row result panel expands with `steps[]` rendered via `RawBlock`

### 3. `/report` per-finding drill-down
Each finding card in `src/routes/report.tsx` gets a "Validate" button.
Clicking it calls `runValidation` and expands a result panel under the
finding with the verdict badge + raw steps. Active-row findings show a
per-card checkbox rather than a global toggle.

### 4. Wiring
- `src/components/app-sidebar.tsx` — add "Validator" nav entry under the
  Analysis section, next to "Report".
- `src/components/finding-validator.tsx` (new) — small shared component
  used by both `/validator` and `/report` so the interaction and result
  rendering stay identical.

## Technical notes

- Uses only `fetch` with `redirect: "manual"`, same Cloudflare-Workers-safe
  primitives as `reauth.functions.ts`; reuses that file's
  `getSetCookieLines`, `dumpHeaders`, `snippet` helpers by extracting
  them to `src/lib/http-probe.ts` (small refactor, no behavior change).
- Verdict typing:
  `type Verdict = "confirmed" | "not-exploitable" | "inconclusive" | "skipped" | "error"`.
- Result NEVER persisted — this is a read-only probe surface, matching
  the reauth probe's model.
- No new tables, no schema changes.

## Out of scope
- SQLi / RCE / auth-bypass PoCs (need payload delivery that modifies data)
- TLS cipher-suite negotiation (raw TLS not available in Worker runtime)
- Rendering executed XSS in a sandboxed iframe — deferred; server-side
  reflection-context classification is enough to prove the class.
