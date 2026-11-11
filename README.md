# WebGuard

Source-code security analysis platform. Upload a website project (ZIP),
and WebGuard scans the source for OWASP-style vulnerabilities, pinpoints
the exact file and line, explains the risk, and suggests a secure fix.

## Monorepo layout

- `apps/api` — backend API (auth, projects, scans, detection engine)
- `apps/web` — frontend SPA
- `packages/core` — shared types
- `packages/analysis` — project profiler + parser/AST layer (detector inputs)

## Getting started

```bash
cp .env.example .env        # then set a strong JWT_SECRET
npm install
docker compose up -d        # Postgres + Redis
npm run db:migrate          # apply Prisma migrations
npm run dev --workspace apps/api
npm run worker              # in a second terminal: processes queued scans
npm test                    # uses TEST_DATABASE_URL (a separate *_test database)
```

## Scanning pipeline

```
POST /api/projects/:id/scans  (multipart, field "file")
  → validate upload   .zip name + application/zip MIME + "PK" magic bytes, ≤ MAX_UPLOAD_BYTES (50 MB)
  → store             raw ZIP via StorageService → artifacts(kind = raw_zip)
  → queue             BullMQ job { scanId } on Redis; scan status = queued
  → worker            status = running → safe-extract → artifacts(kind = extracted)
                      → profile → parse (common AST) → detect → de-dup/correlate
                      → findings rows + summary_json { profile, filesParsed, parseErrors,
                          detectors, findingsTotal, findingsBySeverity,
                          findingsByOwaspCategory, detectorErrors, … }   (one transaction)
                      → completed
                      (any error → failed, summary_json.error, temp dir removed)
```

Clients poll `GET /api/scans/:id` to follow `queued → running → completed | failed`.

`StorageService` is an interface; the current `LocalStorageService` writes under
`STORAGE_DIR`, and an S3-compatible implementation can replace it without changing callers.

**Extraction safety.** Uploaded archives are attacker-controlled, so `ExtractorService`:

- **Blocks zip-slip / path traversal:** every entry path is resolved and must stay inside
  the per-scan temp directory. `..` segments, absolute paths, drive letters, backslashes,
  `:` (alternate data streams), and reserved device names are rejected, and the scan fails.
- **Blocks zip bombs:** caps entry count (`EXTRACT_MAX_FILES`, 20,000), total uncompressed
  size (`EXTRACT_MAX_TOTAL_BYTES`, 500 MB, checked against both declared sizes and the bytes
  actually written), and per-entry compression ratio (`EXTRACT_MAX_COMPRESSION_RATIO`, 100:1).
- **Never materializes symlinks or special files:** symlinks, devices, FIFOs, and encrypted
  entries are skipped. Files are created exclusively (`wx`), so duplicates can't overwrite.

## Analysis inputs

`packages/analysis` produces everything the detection engine consumes. It is framework-free
(pure Node), so it can run in the worker or anywhere else.

**ProjectProfile** (`ProfilerService`, stored as `summary_json.profile`; type in `packages/core`):

- `languages` — per-language file and byte counts (by extension, plus shebang / `<?php` heuristics)
- `frameworks` — runtimes and frameworks from manifests (e.g. `package.json` → Node.js;
  `express`, `react`, `@angular/core`, `next`, `@nestjs/core`, … dependencies)
- `manifests` — manifests and lockfiles (`package.json`, `package-lock.json`, `yarn.lock`,
  `pnpm-lock.yaml`, plus Python/PHP/Ruby/Go/Java equivalents)
- `sensitivePaths` — `.env*`, `Dockerfile`, `docker-compose*`, Terraform, YAML in infra/CI dirs,
  key material, and anything under a served dir (`public/`, `static/`, `www/`, …)
- `sourceFiles` — what to analyze. `node_modules`, `dist`, `build`, `.git` (and similar) are
  never descended; binaries and files over `ANALYSIS_MAX_FILE_BYTES` (1 MB) are skipped and
  counted in `ignored.byReason`.

**Common AST contract** (language-independent):

- `ParsedFile { path, language, ast, sourceText, lineIndex, parseError? }`
- `AstNode { type, rawType, loc { startLine, startCol, endLine, endCol }, children, tags, raw }`
  with a small normalized vocabulary (`Call`, `MemberAccess`, `Assignment`, `StringLiteral`,
  `Function`, …) and resolved names (`db.query`, `req.body.name`). `raw` is the escape hatch
  to the native parser node; `parent` links are available but non-enumerable.
- Reusable queries: `findCalls(['db.query', '*.exec'])`, `findAssignments()`,
  `findStringLiterals()`, `findMemberWrites(['innerHTML'])`, `findTagged('source:*')`,
  `containsSource(node)`, `textOf(file, node)`.

**Source/sink tagging.** After parsing, tag rules mark nodes, e.g. reads of
`req.body / query / params / headers / cookies` → `source:http-input`, and
`innerHTML` writes, `eval`, and `child_process.exec` → `sink:*`. Detectors can supply their
own `TagRule`s. Tagging is syntactic; following destructuring and aliases is left to the
data-flow pass built on top.

**Pluggable parsers.** Each language is a `ParserAdapter` registered in a `ParserRegistry`
keyed by language (`createDefaultParserRegistry()`). The JS/TS adapter uses **@babel/parser**:
one parser for JS/JSX/TS/TSX with decorators, exact locations, and error recovery, pure JS
with no native/WASM bindings (unlike tree-sitter), and no TypeScript program to build (unlike
ts-morph). Adding Python later means writing one adapter and registering it. Unparseable files
never fail a scan: they get a non-fatal `parseError` and the scan moves on.

## Detection engine

**Detector interface** (`packages/analysis/src/detection`):

```ts
interface Detector {
  id: string; // e.g. "A03-sql-injection"
  title: string;
  owaspCategory: OwaspCategory;
  technique: 'pattern' | 'ast' | 'dataflow' | 'dependency' | 'config';
  explanation: string; // default risk explanation
  fixSuggestion: string; // default secure fix
  run(ctx: DetectionContext): RawFinding[] | Promise<RawFinding[]>;
}
```

`DetectionContext` exposes the `ProjectProfile`, every `ParsedFile` (with AST helpers and
source/sink tags), all profiled `sourceFiles`, `manifests`, `configPaths`, sandboxed raw file
access (`readText`), and `snippet(path, lineStart, lineEnd)`. A `RawFinding` carries
`detectorId, owaspCategory, severity, confidence (0–1), filePath, lineStart, lineEnd, snippet,
evidence` and may override the detector's explanation or fix.

**Five technique stages.** `DetectionEngine` runs detectors stage by stage:
`pattern → ast → dataflow → dependency → config`. Each detector runs in isolation. A detector
that throws, rejects, or returns malformed findings (unknown file, bad line range, invalid
severity) is logged and recorded in `summary_json.detectorErrors`, and the scan still completes.
Confidence is clamped to 0–1, and each detector is capped at 5,000 findings.

**Severity & confidence.** Severity reuses `Severity` from `packages/core`
(`critical > high > medium > low > info`). Each finding keeps its detector's confidence.
`filterByConfidence(findings, min)` and `confidenceBand()` (high ≥ 0.8, medium ≥ 0.5) support
report and UI filtering.

**De-duplication & correlation** (`dedupeFindings`):

1. Findings with the same `(detectorId, filePath, lineStart)` collapse into one (strongest kept,
   evidence merged).
2. Findings from different detectors on the same file, line, **and OWASP category** merge into
   one correlated finding. It keeps the highest severity, combines confidence with noisy-OR
   (`1 − Π(1 − cᵢ)`, so agreement raises confidence), and lists every detector in
   `contributingDetectors`. Different categories on the same line stay separate findings.

**Self-registering registry.** A detector module calls `registerDetector({...})` and is
imported once from `detectors/index.ts`. The engine never changes. `example-todo-comment`
(pattern, `info`, confidence 1.0) flags `TODO SECURITY` comments and serves as a template.

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
| POST   | `/api/projects/:id/scans` | Multipart ZIP upload (field `file`) → `201` queued scan                        |
| GET    | `/api/projects/:id/scans` | Scans for a project, newest first                                              |
| GET    | `/api/scans/:id`          | One scan with status and summary                                               |
| GET    | `/api/scans/:id/findings` | Filters: `severity` (one or comma-separated), `owaspCategory`, `minConfidence` |

## Status

- [x] 1. Project scaffold & tooling
- [x] 2. Backend API & JWT authentication
- [x] 3. Projects & scans data model + CRUD
- [x] 4. ZIP upload, safe extraction & job queue
- [x] 5. Project profiler + parser/AST layer
- [x] 6. Detection engine core + detector registry
