# Development

## Prerequisites
- Node 20.11+ and pnpm 11+ (`npm i -g pnpm`)
- PostgreSQL 14+ (via `docker compose up db`, or a local install)

## Setup
```bash
pnpm install
cp .env.example .env          # set AUTH_SECRET; ANTHROPIC_API_KEY optional
pnpm --filter @smb/web db:migrate
pnpm --filter @smb/web db:seed
pnpm dev                      # http://localhost:3000
```

## Demo mode
With `ENABLE_DEMO_SEED=true`, `db:seed` creates:
- Organization **Acme Dental** (flagged `isDemo=true`)
- Assets: `ACME-PC-01`, `ACME-PC-02`, `ACME-PC-03`, `ACME-SERVER`, `ACME-LINUX-01`
- A completed demo scan with realistic, clearly fictional findings
- Demo login from `DEMO_EMAIL` / `DEMO_PASSWORD`

Demo rows are tagged and filtered separately; real scan ingestion never writes to
a demo asset and vice versa. Seeds are local-only and refuse to run when
`NODE_ENV=production`.

## Scripts
| Command | Purpose |
| --- | --- |
| `pnpm dev` | Run the web app |
| `pnpm build` | Build every package + the web app |
| `pnpm typecheck` | `tsc --noEmit` across the workspace |
| `pnpm lint` | ESLint across the workspace |
| `pnpm test` | Vitest unit + integration |
| `pnpm test:e2e` | Playwright golden-path E2E |
| `pnpm --filter @smb/scanner build` | Build the scanner CLI |

## Testing layout
- `packages/*/src/**/__tests__` — unit tests (checks, scoring, prioritization,
  compliance mappings, lifecycle, prompt construction)
- `apps/web/src/**/__tests__` — integration (auth, ingestion, authorization,
  reports) and security (cross-tenant, malformed scan, forged severity)
- `apps/web/e2e` — signup → org → asset → demo scan → score → finding → AI
  summary → resolve → re-scan → score change → report

## Conventions
- Prettier + ESLint enforced; run `pnpm format` before committing.
- No `TODO` for core MVP paths.
- Keep each `SecurityCheck` self-contained in `packages/checks/src/checks/`.
