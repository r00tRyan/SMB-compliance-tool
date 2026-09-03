# Security

This application is security-sensitive: it stores configuration-weakness data
about customer endpoints. It is built to the controls below.

## Reporting a vulnerability

Email the maintainer privately. Do not open a public issue. Please include repro
steps and impact. We aim to acknowledge within 3 business days.

## Controls implemented

### Authentication & sessions
- Passwords hashed with **Argon2id** (`@node-rs/argon2`), per-user salt.
- Sessions are server-signed, `httpOnly`, `SameSite=Lax`, `Secure` in production.
- No plaintext credentials are ever logged or stored.
- Password-reset is architected (token table, single-use, expiring) — email
  delivery is a stub in the MVP.

### Authorization & tenant isolation
- Server-side checks on every route; the frontend never enforces access.
- All org-owned reads/writes flow through `withOrg()` tenant helpers that require
  an `organizationId` from the session's active membership.
- Role gate: `OWNER`/`ADMIN` may mutate assets and generate reports; `MEMBER`
  may view. Enforced in route handlers.
- Automated cross-tenant tests (`tenant-isolation.test.ts`).

### Input validation
- Every request body/query parsed with Zod; unknown keys rejected.
- Scan payloads: byte-size cap (`SCAN_MAX_BYTES`) before parsing; strict schema;
  `checkId` must exist in the registry; client-supplied `severity`/`category`
  are **ignored** in favor of server registry values.

### Database
- Prisma parameterizes all queries; no string-built SQL.
- Foreign keys + `onDelete: Cascade` for org-owned trees; unique constraints on
  `(assetId, checkId, status=OPEN)` semantics enforced in code + partial index.

### Transport & headers
- `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
  and a restrictive `Content-Security-Policy` set in `next.config` + middleware.
- CSRF: state-changing API routes require a same-origin `Origin`/`Sec-Fetch-Site`
  check in addition to the session cookie.

### Secrets
- All secrets via environment variables, read in server code only.
- `ANTHROPIC_API_KEY` is never sent to the browser and never appears in any
  client bundle. AI calls originate from route handlers.

### Rate limiting
- In-memory fixed-window limiter on `/api/scans` and `/api/ai/*`
  (per organization). Swappable for Redis later via the `RateLimiter` interface.

### AI safety
- Structured, minimized input only (see `AI.md`). Scanner evidence is passed as
  clearly delimited *data*, never concatenated into the system prompt.
- Output is validated (no fabricated check IDs, length bounds, no secret-looking
  strings) before display.

### Error handling & logging
- No stack traces to clients; every handler returns a safe shape
  `{ error: { code, message } }`.
- Structured server logs (`pino`) with a redaction list; request ids on errors.
- `AuditLog` records security-relevant events (see list in `THREAT_MODEL.md`).

## Explicitly out of scope (by design)
The scanner does not exploit, brute-force, dump credentials, read personal files,
capture screenshots/keystrokes, persist, disable security software, or scan
arbitrary network targets. See `SCANNER.md` §Safety.
