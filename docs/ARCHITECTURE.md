# Architecture

## Shape

A **modular monolith**: one deployable web application plus a standalone scanner
CLI. PostgreSQL is the only stateful dependency. The Anthropic API is an optional
external dependency used purely for narration.

```
┌────────────┐   result.json    ┌───────────────────────────────────────────┐
│ security-  │ ───────────────▶ │  apps/web  (Next.js, modular monolith)     │
│ agent CLI  │  POST /api/scans │                                           │
└────────────┘                  │  route handlers ─┐                        │
   read-only                    │                  ▼                        │
   collectors                   │   ingestion → risk-engine → compliance    │
                                │        │            │           │        │
                                │        ▼            ▼           ▼        │
                                │      Prisma  ───────────────▶ PostgreSQL │
                                │        │                                 │
                                │        ▼                                 │
                                │   dashboard (React server components)     │
                                │        │                                 │
                                │        ▼   (optional, degrades)           │
                                │   packages/ai ──▶ Anthropic API           │
                                └───────────────────────────────────────────┘
```

## Package boundaries

| Package | Responsibility | Depends on |
| --- | --- | --- |
| `@smb/shared` | Cross-cutting TypeScript types; Zod schemas. The **scan-result schema** is the ingestion trust boundary. | — |
| `@smb/checks` | Declarative `SecurityCheck` definitions + a registry keyed by `checkId`. This is the **single source of truth for severity, category, rationale, remediation, framework mappings**. | `@smb/shared` |
| `@smb/scanner` | Platform collectors (Windows/Linux), a check runner, and the `security-agent` CLI. Produces schema-valid JSON. **Read-only.** | `@smb/shared`, `@smb/checks` |
| `@smb/risk-engine` | Deterministic org/category scoring + remediation-priority ranking. Pure functions, no I/O. | `@smb/shared`, `@smb/checks` |
| `@smb/compliance` | Curated CIS Controls v8 + NIST CSF 2.0 mapping metadata and coverage math. | `@smb/shared`, `@smb/checks` |
| `@smb/ai` | Anthropic client wrapper, structured prompt builder, output validators, graceful-failure results. | `@smb/shared` |
| `@smb/web` | Auth, multi-tenancy, HTTP API, scan ingestion, findings lifecycle, dashboard, reporting. | all of the above |

Rule: **adding a security check touches only `@smb/checks`** (definition) and
`@smb/scanner` (a collector, if a new data source is needed). The core scanner
runner, risk engine, and web app do not change.

## Trust model (why the layers are split)

The spec's central reliability requirement is separating **Detection** from
**Interpretation** from **Recommendation**:

- **Detection** — produced only by the scanner. Stored verbatim as `evidence`.
- **Interpretation** — `status` (PASS/FAIL/WARN/ERROR/NOT_APPLICABLE) is computed
  by the check's own `evaluate()` from evidence. `severity` is looked up from the
  **server-side registry**, never from the uploaded JSON.
- **Recommendation** — deterministic text from the check definition.
- **AI-generated** — narration layered on top, never overwriting the above.

Reports render these four provenance classes distinctly (see `REPORTING.md`).

## Data flow: a scan

1. `security-agent scan` runs each applicable check's collector, evaluates
   status locally, writes `result.json` (schema `1.0`).
2. Client `POST /api/scans` with the JSON + `assetId`. The route:
   - enforces size limit, then `SecurityScanResult` Zod parse (strict, no
     unknown keys);
   - resolves the asset **within the caller's organization** (404 otherwise);
   - for each finding, looks up the check in `@smb/checks`. Unknown `checkId` →
     rejected. `severity`/`category` are taken from the registry, not the JSON.
3. Findings are upserted against existing OPEN findings for `(asset, checkId)`:
   - new → `OPEN`, `firstDetectedAt = now`;
   - still failing → `lastDetectedAt = now`;
   - previously failing, now PASS → `RESOLVED`, `resolvedAt = now`.
4. `risk-engine` recomputes org + category scores from the current OPEN findings.
5. `AuditLog` rows written for `scan.completed` and each `finding.*` transition.

## Multi-tenancy

Every org-owned row has `organizationId`. All queries go through helpers in
`apps/web/src/server/tenant.ts` that require an `organizationId` argument derived
from the authenticated session's active membership. There is no code path that
loads an org-owned row by id alone. Tests in
`apps/web/src/server/__tests__/tenant-isolation.test.ts` assert Org A cannot read
or mutate Org B's assets, scans, findings, or reports.

## Tech choices

Next.js (App Router) + React + TypeScript + Tailwind; Prisma + PostgreSQL; Auth.js
(credentials, Argon2id hashing, httpOnly cookies); Zod for every external input;
Vitest for unit/integration; Playwright for the golden-path E2E; `@react-pdf/renderer`
for PDF export. Rationale for deviations from the brief is inline in the relevant
doc.
