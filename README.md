# WebGuard

Source-code security analysis platform. Upload a website project (ZIP),
and WebGuard scans the source for OWASP-style vulnerabilities, pinpoints
the exact file and line, explains the risk, and suggests a secure fix.

## Monorepo layout

- `apps/api` — backend API (auth, projects, scans, detection engine)
- `apps/web` — frontend SPA
- `packages/core` — shared types

## Getting started

```bash
npm install
docker compose up -d        # Postgres + Redis
npm run dev --workspace apps/api
npm test
```

## Status

- Step 1: Monorepo foundation — npm workspaces, strict TypeScript, ESLint + Prettier, Express `GET /api/health` with test, shared core types, CI workflow, Docker Compose (Postgres 16 + Redis 7).
