# syntax=docker/dockerfile:1
# VibeSec API: Fastify + better-sqlite3, run from TypeScript source with tsx (same as `npm run start`).

# ---- deps: install workspace dependencies (build tools only here, in case better-sqlite3 has no prebuild) ----
FROM node:24-bookworm-slim AS deps
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Manifests first for layer caching. Every workspace manifest is copied so `npm ci` can validate the lockfile.
COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
# API + shared + root (root devDependencies carry tsx); the web workspace's deps are skipped.
RUN npm ci --no-audit --no-fund -w @vibesec/api -w @vibesec/shared --include-workspace-root

# ---- runtime ----
FROM node:24-bookworm-slim
# git is required at startup (GitService.init exits otherwise); ca-certificates for https clones.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Manifests + node_modules (root and any non-hoisted per-workspace ones).
COPY --from=deps /app ./
COPY tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY apps/api ./apps/api
COPY fixtures ./fixtures
# /data holds the SQLite DB and scan checkouts; pre-created so a fresh named volume inherits node's ownership.
RUN mkdir -p /data/work && chown -R node:node /data
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=4000 \
    DB_PATH=/data/vibesec.db \
    WORK_DIR=/data/work
USER node
WORKDIR /app/apps/api
EXPOSE 4000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||4000)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
# Equivalent of `npm run start -w @vibesec/api`, without npm in the signal path so SIGTERM reaches the server.
CMD ["/app/node_modules/.bin/tsx", "src/server.ts"]
