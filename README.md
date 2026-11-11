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

## Data model

```
users 1──* projects 1──* scans 1──* findings
                              └──* artifacts
```

| Table       | Purpose                                                          | Key columns                                                                                                                                            |
| ----------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `users`     | Account owners                                                   | `email` (unique), `password_hash`                                                                                                                      |
| `projects`  | A website codebase owned by a user                               | `user_id → users`, `name`                                                                                                                              |
| `scans`     | One analysis run of a project                                    | `project_id → projects`, `status` (`queued`/`running`/`completed`/`failed`), `started_at`, `finished_at`, `summary_json`                               |
| `findings`  | A detected vulnerability at a file/line                          | `scan_id → scans`, `detector_id`, `owasp_category`, `severity`, `confidence` (0–1), `file_path`, `line_start`, `line_end`, `snippet`, `fix_suggestion` |
| `artifacts` | Files produced for a scan (uploaded ZIP, extracted tree, report) | `scan_id → scans`, `kind` (`raw_zip`/`extracted`/`report`), `storage_key`                                                                              |

All foreign keys cascade on delete (deleting a project removes its scans, findings, and
artifacts) and are indexed; `findings` also has a composite index on `(scan_id, severity)`.

### Projects & scans API

All routes require `Authorization: Bearer <token>`. Resources owned by another user return `404`.

| Method | Path                      | Notes                                                                          |
| ------ | ------------------------- | ------------------------------------------------------------------------------ |
| POST   | `/api/projects`           | `{ name }` → `201` project                                                     |
| GET    | `/api/projects`           | Current user's projects, newest first                                          |
| GET    | `/api/projects/:id`       | One project                                                                    |
| PATCH  | `/api/projects/:id`       | `{ name }` → renamed project                                                   |
| DELETE | `/api/projects/:id`       | `204`; cascades to scans/findings/artifacts                                    |
| POST   | `/api/projects/:id/scans` | Creates a `queued` scan → `201`                                                |
| GET    | `/api/projects/:id/scans` | Scans for a project, newest first                                              |
| GET    | `/api/scans/:id`          | One scan with status and summary                                               |
| GET    | `/api/scans/:id/findings` | Filters: `severity` (one or comma-separated), `owaspCategory`, `minConfidence` |

## Status

- [x] 1. Project scaffold & tooling
- [x] 2. Backend API & JWT authentication
- [x] 3. Projects & scans data model + CRUD
