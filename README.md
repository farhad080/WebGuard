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
cp .env.example .env        # then set a strong JWT_SECRET
npm install
docker compose up -d        # Postgres + Redis
npm run db:migrate          # apply Prisma migrations
npm run dev --workspace apps/api
npm test                    # uses TEST_DATABASE_URL (a separate *_test database)
```

## Authentication

All auth endpoints live under `/api/auth` and accept/return JSON.

| Method | Path                 | Body                  | Success             | Errors                                    |
| ------ | -------------------- | --------------------- | ------------------- | ----------------------------------------- |
| POST   | `/api/auth/register` | `{ email, password }` | `201 { id, email }` | `400` invalid input, `409` email taken    |
| POST   | `/api/auth/login`    | `{ email, password }` | `200 { token }`     | `401` invalid email or password (generic) |
| GET    | `/api/auth/me`       | —                     | `200 { id, email }` | `401` missing/invalid token               |

Passwords must be at least 8 characters and are hashed with argon2id. `login` returns an
HS256 JWT (signed with `JWT_SECRET`, 1-hour expiry, payload `{ sub, email }`). Send it on
protected routes as:

```
Authorization: Bearer <token>
```

## Status

- [x] 1. Project scaffold & tooling
- [x] 2. Backend API & JWT authentication
