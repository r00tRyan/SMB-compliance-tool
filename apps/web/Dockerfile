# Multi-stage build for the web app. Run from the repo root:
#   docker compose up --build
FROM node:22-bookworm-slim AS base
ENV PNPM_HOME=/pnpm
ENV PATH="$PNPM_HOME:$PATH"
# Prisma's query/schema engines need libssl; bookworm-slim ships without it.
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*
RUN corepack enable && corepack prepare pnpm@11.25.0 --activate
WORKDIR /app

FROM base AS deps
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json .npmrc ./
COPY apps/web/package.json apps/web/package.json
COPY packages ./packages
RUN pnpm install --frozen-lockfile

FROM base AS build
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages ./packages
COPY . .
# `next build` evaluates server modules (incl. env validation). These are
# build-time placeholders only — real values are injected at runtime by
# docker-compose. They are never baked into the running server.
ENV DATABASE_URL="postgresql://build:build@localhost:5432/build?schema=public"
ENV AUTH_SECRET="build-time-placeholder-not-a-real-secret"
ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm --filter @smb/web build

FROM base AS runner
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=build /app ./
EXPOSE 3000
# Apply migrations, run the demo seed if ENABLE_DEMO_SEED=true, then start.
CMD ["sh", "-c", "pnpm --filter @smb/web db:migrate:deploy && (pnpm --filter @smb/web db:seed || true) && pnpm --filter @smb/web start"]
