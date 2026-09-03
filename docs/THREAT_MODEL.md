# Threat Model

Scope: the web application, its API, the scan-ingestion path, and the AI layer.
Out of scope: the customer's own endpoint security, physical access, and the
security of the Anthropic API itself.

## Assets to protect
- Endpoint configuration-weakness data (findings, evidence) per organization.
- User credentials and sessions.
- The Anthropic API key.
- Report contents.

## Actors
- **Legitimate user** (OWNER/ADMIN/MEMBER of one or more orgs).
- **Cross-tenant attacker** — authenticated user of Org A targeting Org B.
- **Malicious scan submitter** — controls the JSON posted to `/api/scans`.
- **Compromised endpoint** — sends forged/hostile scan data with valid creds.
- **Prompt-injection payload** — hostile text embedded in scanner evidence.
- **Session thief** — has a stolen cookie.
- **API abuser** — floods AI/scan endpoints to run up cost.

## Threats & mitigations

| # | Threat | Vector | Mitigation |
| --- | --- | --- | --- |
| T1 | Read another org's data | Guessed/enumerated ids on any GET | All org-owned reads go through `withOrg(organizationId)`; no id-only lookups; automated isolation tests |
| T2 | Mutate another org's data | PATCH/POST with foreign id | Same tenant helpers on writes; role gate; ownership re-checked inside the transaction |
| T3 | Forged severity / inflated risk | `severity: "CRITICAL"` in uploaded JSON | Server ignores client severity/category; authoritative values from `@smb/checks` registry keyed by `checkId` |
| T4 | Unknown/booby-trapped `checkId` | Arbitrary strings in `findings[].checkId` | Registry lookup required; unknown ids rejected with 422; no dynamic code paths keyed on `checkId` |
| T5 | Ingestion resource exhaustion | Huge/deeply-nested JSON | Byte cap before parse; strict Zod schema with array length bounds; no recursion on user data |
| T6 | Evidence XSS in dashboard/report | HTML/JS in `evidence` string | React escaping; evidence rendered as text; PDF renderer escapes; CSP |
| T7 | Prompt injection via evidence | "Ignore previous instructions…" inside evidence | Evidence passed only inside a delimited `<finding_data>` block as data; system prompt is static; output validators reject fabricated ids and instruction-echo; see `AI.md` |
| T8 | Stolen session reuse | Exfiltrated cookie | `httpOnly`+`Secure`+`SameSite=Lax`; short idle lifetime; server-side session invalidation on password reset; audit trail |
| T9 | CSRF on state-changing routes | Cross-site form/fetch | Same-origin `Origin`/`Sec-Fetch-Site` assertion + cookie; no GET side effects |
| T10 | AI/scan cost abuse | Rapid repeated requests | Per-org fixed-window rate limiter; `ANTHROPIC_MAX_TOKENS` ceiling; AI features require a completed scan |
| T11 | Secret disclosure | Key in client bundle / logs / errors | Key read only in server handlers; log redaction; safe error shape; CI grep guard in `apps/web` build |
| T12 | Account takeover via weak reset | Predictable/replayable token | 256-bit random token, hashed at rest, single-use, 1-hour expiry, session revocation on use |
| T13 | Privilege escalation | MEMBER performing ADMIN action | Role checked in handler against active membership row, not a client claim |
| T14 | Malicious PDF/report access | Guessing report ids | Reports are org-owned; `withOrg` on fetch + download route |

## Residual risk / accepted for MVP
- Rate limiter is in-memory (per instance). Acceptable for single-instance MVP;
  interface allows a Redis backend later.
- Email delivery for password reset is stubbed; flow is present but inert.
- No 2FA in the MVP (architecture leaves room via an `authFactors` table).
