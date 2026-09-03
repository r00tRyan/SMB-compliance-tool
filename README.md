# SMB Security Posture & Compliance Readiness Platform

A lightweight security assessment platform for small businesses that don't have
dedicated cybersecurity staff. It runs read-only configuration checks against
Windows and Linux endpoints, scores the results with a deterministic risk model,
maps gaps to recognized security controls (CIS Controls, NIST CSF), explains them
in plain English, and verifies fixes on re-scan.

> **Positioning.** This is a **security posture assessment and compliance
> readiness** tool. It identifies configuration gaps and maps them to recognized
> security controls. It does **not** make legal or regulatory compliance
> determinations, and no report it produces is an audit or certification.

## Project status

MVP under active construction. What exists and is verified:

- **Core packages** — `shared`, `checks` (26 read-only Windows/Linux checks),
  `risk-engine` (deterministic scoring), `compliance` (CIS v8 + NIST CSF 2.0
  mapping), `ai` (Anthropic explanation layer with guardrails + graceful
  fallback), `scanner` — all built and unit-tested (86 tests green).
- **Scanner CLI** (`security-agent`) — verified running against a real Windows host.
- **Web app** — Next.js app with Prisma schema, Argon2id auth, tenant-isolated
  data access, the scan-ingestion trust boundary, dashboard / assets / findings /
  finding detail / scans / reports / activity pages, demo mode, PDF export.
  `pnpm typecheck`, `pnpm lint`, and `next build` all pass.

Not yet run end-to-end in this environment: Prisma migrations, the demo seed, and
the Playwright golden-path test — all need a running PostgreSQL (`docker compose up`
or a local install). See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

## The product loop

**Discover → Assess → Prioritize → Explain → Remediate → Verify → Report**

| Stage | What it does |
| --- | --- |
| Discover | Register endpoints (assets) for an organization. |
| Assess | Run the scanner (real local scan or demo scan); ingest structured JSON. |
| Prioritize | Deterministic risk + remediation-priority engine surfaces "fix these first". |
| Explain | Deterministic remediation guidance, optionally narrated by Claude. |
| Remediate | Human-guided fixes with a "who should handle it" + effort estimate. |
| Verify | Re-scan re-checks the exact configuration; findings move OPEN → RESOLVED. |
| Report | Professional assessment report (online + PDF) with a clear disclaimer. |

## Architecture

Modular monolith. No microservices, no Kubernetes, no queues.

```
apps/
  web/            Next.js dashboard + authenticated API + Prisma/PostgreSQL
packages/
  shared/         Types + Zod schemas (scan-result schema is the trust boundary)
  checks/         SecurityCheck definitions + registry (authoritative severity)
  scanner/        Read-only collectors + `security-agent` CLI (Windows/Linux)
  risk-engine/    Deterministic scoring + remediation prioritization
  compliance/     CIS / NIST CSF control mappings (curated SMB subset)
  ai/             Anthropic client, prompt construction, output guardrails
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quick start

```bash
git clone <this-repo>
cd smb-compliance-tool
cp .env.example .env          # edit AUTH_SECRET; ANTHROPIC_API_KEY optional
docker compose up             # Postgres + web, migrations + demo seed applied
# open http://localhost:3000  — sign in with the demo credentials from .env
```

Without Docker:

```bash
pnpm install
# point DATABASE_URL at a local PostgreSQL 14+ instance in .env
pnpm --filter @smb/web db:migrate
pnpm --filter @smb/web db:seed
pnpm dev
```

## Running a real scan

```bash
pnpm --filter @smb/scanner build
node packages/scanner/dist/cli.js scan --output result.json
# then upload result.json in the dashboard, or POST it to /api/scans
```

See [`docs/SCANNER.md`](docs/SCANNER.md) and [`docs/CHECKS.md`](docs/CHECKS.md).

## Demo mode

`ENABLE_DEMO_SEED=true` + `pnpm db:seed` creates the fictional **Acme Dental**
organization (5 assets, realistic findings). All demo data is tagged `DEMO DATA`
and is never mixed with real scan results. See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

## Anthropic configuration

Set `ANTHROPIC_API_KEY` in `.env`. AI is an **explanation/reporting layer only** —
it never determines findings, severity, or control mappings, and the app is fully
functional without it. See [`docs/AI.md`](docs/AI.md).

## Documentation

| Doc | Contents |
| --- | --- |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, package boundaries, data flow |
| [SECURITY.md](docs/SECURITY.md) | Security controls, reporting a vulnerability |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threats + mitigations |
| [API.md](docs/API.md) | Authenticated HTTP API reference |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Local setup, demo mode, testing |
| [SCANNER.md](docs/SCANNER.md) | Scanner CLI, safety boundaries, output format |
| [CHECKS.md](docs/CHECKS.md) | Every security check, rationale, remediation |
| [AI.md](docs/AI.md) | AI integration, prompts, guardrails, failure handling |
| [REPORTING.md](docs/REPORTING.md) | Report structure, integrity model, PDF export |

## License

UNLICENSED — private project.
