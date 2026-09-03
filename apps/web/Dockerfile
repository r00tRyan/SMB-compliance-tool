# Multi-stage build for the web app. Run from the repo root:
#   docker build -f apps/web/Dockerfile -t smb-web .
FROM node:20-bookworm-slim AS base
ENV PNPM_HOME=/pnpm
ENV PATH="$PNPM_HOME:$PATH"
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
RUN pnpm --filter @smb/web exec prisma generate
RUN pnpm --filter @smb/web build

FROM base AS runner
ENV NODE_ENV=production
COPY --from=build /app ./
EXPOSE 3000
# Apply migrations + optional demo seed, then start.
CMD ["sh", "-c", "pnpm --filter @smb/web db:migrate:deploy && pnpm --filter @smb/web db:seed || true; pnpm --filter @smb/web start"]
