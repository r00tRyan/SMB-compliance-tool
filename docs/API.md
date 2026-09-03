# HTTP API

All routes are under `/api`. All require an authenticated session cookie unless
noted. State-changing routes also require a same-origin request. Responses on
error use `{ "error": { "code": string, "message": string } }` with an
appropriate status. Internal database models are never returned directly; routes
return explicit DTOs.

## Auth
| Method | Path | Body | Notes |
| --- | --- | --- | --- |
| POST | `/api/auth/register` | `{ email, password, organizationName }` | Creates user + org + OWNER membership |
| POST | `/api/auth/login` | `{ email, password }` | Sets session cookie |
| POST | `/api/auth/logout` | — | Clears session |
| POST | `/api/auth/password-reset/request` | `{ email }` | Always 202 (no user enumeration); email stubbed |
| POST | `/api/auth/password-reset/confirm` | `{ token, password }` | Single-use token; revokes sessions |

## Assets  (`OWNER`/`ADMIN` to mutate)
| Method | Path | Body / query | Notes |
| --- | --- | --- | --- |
| GET | `/api/assets` | `?platform&status` | Org-scoped list with score + open-finding count |
| POST | `/api/assets` | `{ name, platform, description? }` | |
| GET | `/api/assets/:id` | — | Detail + scan history + category scores |
| PATCH | `/api/assets/:id` | `{ name?, description?, status? }` | |
| DELETE | `/api/assets/:id` | — | Cascades scans/findings |

## Scans
| Method | Path | Body | Notes |
| --- | --- | --- | --- |
| POST | `/api/scans` | `{ assetId, result: SecurityScanResult }` | Ingestion trust boundary. Size-capped, strict schema, registry-authoritative severity. Rate-limited per org. |
| GET | `/api/scans` | `?assetId` | Scan history with score deltas |
| GET | `/api/scans/:id` | — | Scan detail: resolved / new / unchanged counts |
| POST | `/api/scans/demo` | `{ assetId, scenario? }` | Runs a demo scan (demo org only) |

## Findings
| Method | Path | Body / query | Notes |
| --- | --- | --- | --- |
| GET | `/api/findings` | `?severity&platform&category&status&assetId` | Org-scoped |
| GET | `/api/findings/:id` | — | Full detail incl. remediation + control mappings + evidence |
| PATCH | `/api/findings/:id` | `{ status, note? }` | Lifecycle transition; writes `AuditLog` |
| POST | `/api/findings/:id/rescan` | — | Re-runs the single check's verification (demo) or returns upload instructions (real) |

## Reports  (`OWNER`/`ADMIN`)
| Method | Path | Body | Notes |
| --- | --- | --- | --- |
| POST | `/api/reports` | `{ includeAiNarrative?: boolean }` | Generates a report snapshot |
| GET | `/api/reports` | — | Report history |
| GET | `/api/reports/:id` | — | Report JSON (provenance-tagged sections) |
| GET | `/api/reports/:id/pdf` | — | `application/pdf` |

## AI  (rate-limited; all degrade gracefully — see `AI.md`)
| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| POST | `/api/ai/executive-summary` | `{ scanId? }` | `{ text, model, degraded }` |
| POST | `/api/ai/remediation-plan` | `{ scanId? }` | `{ items[], degraded }` |
| POST | `/api/ai/explain-finding` | `{ findingId }` | `{ text, degraded }` |

When `ANTHROPIC_API_KEY` is unset or the call fails, AI routes return
`200 { degraded: true, text: <deterministic fallback> }` — never a 5xx that
breaks the page.
