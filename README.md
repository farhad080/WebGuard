# WebGuard

Source-code security analysis platform. Upload a website project (ZIP),
and WebGuard scans the source for OWASP-style vulnerabilities, pinpoints
the exact file and line, explains the risk, and suggests a secure fix.
Scans are compared over time, so you can see what was fixed, what is new, and how the risk
grade trends.

WebGuard is a **static** analyzer. It reads source code and never runs it. Some weakness
classes need a running application or a human to confirm; see
[What WebGuard can and cannot detect](#what-webguard-can-and-cannot-detect).

## Quick demo

```bash
npm install
npm run demo
```

`npm run demo` does the following:

- starts Postgres and Redis (`docker compose up -d --wait`)
- applies the migrations and builds the shared packages
- **seeds a demo account** and the deliberately vulnerable **Acme Shop** project, and queues
  a scan of it
- starts the API, worker and web app

Open http://localhost:5173 and sign in as **`demo@webguard.local` / `webguard-demo`**. Open
the Acme Shop project and select its scan to see the dashboard, findings, Monaco code view,
and the HTML/PDF/JSON reports. Ctrl+C stops everything.

The scan finds SQL injection, reflected XSS, a hardcoded Stripe-style secret, MD5 password
hashing, a vulnerable dependency and a typosquatted one, and server misconfiguration.

- `npm run demo -- --setup` stops after seeding, if you'd rather start the apps yourself.
- `npm run seed:demo` re-seeds at any time. It resets the demo password and queues another
  scan, so the History & compare view fills up. It also writes `apps/api/demo/acme-shop.zip`
  for manual uploads.

Requires Docker and Node 20+. The demo account has a published password, so the seed refuses
to run with `NODE_ENV=production`.

## Monorepo layout

- `apps/api`: backend API (auth, projects, scans, reports) and the scan worker
- `apps/api/demo`: the vulnerable demo project (generated; source only, never run)
- `apps/web`: frontend SPA and the Playwright e2e test
- `packages/core`: shared types
- `packages/analysis`: profiler, parser/AST layer, taint tracing, detectors and remediation

## Getting started

```bash
cp .env.example .env        # then set a strong JWT_SECRET
npm install
docker compose up -d        # Postgres + Redis
npm run db:migrate          # apply Prisma migrations
npm run dev --workspace apps/api
npm run worker              # in a second terminal: processes queued scans
npm run dev --workspace apps/web   # in a third terminal: SPA on http://localhost:5173
npm test                    # uses TEST_DATABASE_URL (a separate *_test database)
```

Open http://localhost:5173, create an account, create a project, and drop a ZIP of its source.

## Architecture

```
 Browser ──► apps/web (React SPA) ──/api──► apps/api (Express)
                                            │  auth · projects · scans · findings · compare · reports
                                            │  rate limits · CORS · ownership checks
                         ┌──────────────────┼───────────────────────┐
                         ▼                  ▼                       ▼
                    PostgreSQL         Redis (BullMQ)         StorageService
                    users, projects,   scan + report-pdf      uploads, extracted trees,
                    scans, findings    jobs                   PDF reports (never web-served)
                                            │
                                            ▼
                                     worker process
                                     claim → safe-extract ──► analysis thread (isolated)
                                                              profile → parse → detect
                                                              → de-dup → remediate
                                     ◄── findings + summary ──┘
                                     persist + rollup/grade → completed | failed → cleanup
```

- **apps/web** polls the API and never blocks on a scan.
- **apps/api** handles HTTP and enqueues jobs. The **worker** (the same codebase,
  `npm run worker`) processes them.
- **packages/analysis** is pure Node with no DB or network dependency. The worker runs it in
  a resource-limited worker thread, so the scanner stays safe against the code it analyzes
  (see [Scanner hardening](#scanner-hardening)).

Each stage is described below:
[pipeline](#scanning-pipeline) → [analysis inputs](#analysis-inputs) →
[detection engine](#detection-engine) → [detectors](#detectors) →
[remediation](#remediation) → [reports](#reports).

## Scanning pipeline

```
POST /api/projects/:id/scans  (multipart, field "file")
  → validate upload   .zip name + application/zip MIME + "PK" magic bytes, ≤ MAX_UPLOAD_MB (512 MB)
  → store             raw ZIP via StorageService → artifacts(kind = raw_zip)
  → queue             BullMQ job { scanId } on Redis; scan status = queued
  → worker            status = running → safe-extract (dependency/build/VCS dirs skipped)
                        → artifacts(kind = extracted)
                      → analysis thread (heap cap + wall-clock timeout, network guard):
                          profile → parse (common AST) → detect → de-dup/correlate → remediate
                      → findings rows + summary_json { extractedFiles, skippedDirs,
                          skippedFileCount, profile, filesParsed, parseErrors, detectors,
                          rollup, detectorErrors, informationalNotes, … }
                          (one transaction)
                      → completed
                      (any error or exceeded limit → failed + summary_json.error)
                      → cleanup: temp dir removed, raw upload deleted
                        (failed scans also lose their extracted tree)
```

Clients poll `GET /api/scans/:id` to follow `queued → running → completed | failed`.

`StorageService` is an interface; the current `LocalStorageService` writes under
`STORAGE_DIR`, and an S3-compatible implementation can replace it without changing callers.

**Extraction safety.** Uploaded archives are attacker-controlled, so `ExtractorService`:

- **Blocks zip-slip / path traversal:** every entry path is resolved and must stay inside
  the per-scan temp directory. `..` segments, absolute paths, drive letters, backslashes,
  `:` (alternate data streams), and reserved device names are rejected, and the scan fails.
- **Skips dependency, build, and VCS directories:** entries under `node_modules/`, `.git/`,
  `dist/`, … (`EXTRACT_IGNORE_DIRS`, see below) are never written and never counted toward
  any cap. Their paths are still checked, so a traversal name fails the scan even there.
- **Blocks zip bombs:** caps entry count (`MAX_EXTRACTED_FILES`, 100,000), total uncompressed
  size (`MAX_EXTRACTED_MB`, 2048 MB, checked against both declared sizes and the bytes
  actually written), and per-entry compression ratio (`MAX_COMPRESSION_RATIO`, 200:1).
- **Never materializes symlinks or special files:** symlinks, devices, FIFOs, and encrypted
  entries are skipped. Files are created exclusively (`wx`), so duplicates can't overwrite.

### Limits & configuration

Every upload and extraction limit is read from the environment (no rebuild needed; the
API and worker pick up a change on restart). Defaults fit projects of a few hundred MB:

| Variable                | Default         | What it limits                                                                                             |
| ----------------------- | --------------- | ---------------------------------------------------------------------------------------------------------- |
| `MAX_UPLOAD_MB`         | 512             | Size of the uploaded ZIP. Over it → `413 {"error":"File exceeds the 512 MB upload limit …","limitMb":512}` |
| `UPLOAD_TIMEOUT_MS`     | 600000 (10 min) | How long one upload request may take to arrive (Node `requestTimeout`) and may stall on the upload route   |
| `MAX_EXTRACTED_MB`      | 2048            | Total uncompressed size of the archive                                                                     |
| `MAX_EXTRACTED_FILES`   | 100000          | Entries (files + directories) outside ignored directories                                                  |
| `EXTRACT_IGNORE_DIRS`   | see below       | Comma-separated directory names to skip (replaces the default list; `none` extracts everything)            |
| `MAX_COMPRESSION_RATIO` | 200             | Uncompressed:compressed ratio of any entry of 1 MB or more                                                 |

**Skipped directories.** Real projects are often zipped with their installed dependencies
and build output: one with `node_modules` easily has 90,000+ files, almost none of them the
project's own code. Any directory with one of these names, at any depth (so
`packages/web/node_modules/` too), is skipped during extraction, before the file-count, size,
and ratio caps apply, and the same list is used by profiling and parsing:

```
node_modules  bower_components  vendor  .venv  venv  __pycache__            (dependencies)
dist  build  out  .next  .nuxt  coverage  target  .gradle  .cache           (build output, caches)
.git  .hg  .svn                                                             (version control)
```

- Only directory names match: a file named `build`, or a directory named `builder`, is kept.
- Manifests and lockfiles at the project root (or any non-ignored directory) are always
  extracted, so the dependency detector still analyzes `package.json`, `package-lock.json`,
  `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile*`, `composer.json/lock`,
  `go.mod/sum`, …. The copies inside `node_modules/` are not needed: the root lockfile
  already pins every installed version.
- The scan reports what was skipped. `summary_json` has `extractedFiles`, `skippedFileCount`,
  and `skippedDirs` (the top-most skipped directories, up to 100). The scan page and the
  reports show it as "ignored N dependency/build files". It is informational, not an error.
- `MAX_EXTRACTED_FILES` remains a safety net for archives whose own files are too many.
- To scan a directory on the list (say your sources live in `build/`), set
  `EXTRACT_IGNORE_DIRS` to the names you do want skipped, e.g.
  `EXTRACT_IGNORE_DIRS=node_modules,.git,dist`.

**Other notes.**

- The multipart upload is streamed to disk by multer; the JSON body parser (100 kB) only
  handles `application/json`, so it never caps an upload.
- The SPA reads the upload cap from `GET /api/limits` and refuses a larger file before
  sending it; the server enforces the same cap regardless.
- Hitting an extraction cap fails the scan cleanly (`status: failed`, the reason in
  `summary_json.error`, e.g. `Archive exceeds the maximum uncompressed size (2048 MB;
MAX_EXTRACTED_MB)`) and removes the partial extraction. Zip-slip checks are unaffected
  by any of these settings.
- A large project also needs time and memory to analyze: see `SCAN_TIMEOUT_MS` and
  `SCAN_MAX_HEAP_MB` below. Only files up to `ANALYSIS_MAX_FILE_BYTES` (1 MB) are parsed, so
  big binaries in the archive cost disk and extraction time, not analysis time.
- The older byte-based names (`MAX_UPLOAD_BYTES`, `EXTRACT_MAX_TOTAL_BYTES`,
  `EXTRACT_MAX_FILES`, `EXTRACT_MAX_COMPRESSION_RATIO`) still work when the new ones are unset.

**Development proxy.** The Vite dev/preview proxy (`/api` → the API) has no body-size limit,
and the Vite server's own request timeout is raised to `UPLOAD_TIMEOUT_MS`, so nothing extra
is needed locally.

**Production reverse proxy (nginx).** nginx rejects request bodies over 1 MB by default
(`413 Request Entity Too Large`, before the request reaches the API) and gives up on slow
uploads after 60 s. Raise both to match the API (not part of this repo):

```nginx
location /api/ {
    proxy_pass http://webguard_api;
    client_max_body_size  512m;   # ≥ MAX_UPLOAD_MB
    client_body_timeout   600s;   # ≈ UPLOAD_TIMEOUT_MS
    proxy_read_timeout    600s;
    proxy_send_timeout    600s;
    proxy_request_buffering off;  # stream the upload to the API instead of spooling it first
}
```

Other proxies have equivalents (e.g. a load balancer's maximum request size and idle timeout).

## Scanner hardening

WebGuard analyzes **untrusted code**, so the scanner treats every upload as hostile.

- **Uploaded code is never executed.** The analysis only reads files as text and parses them
  into ASTs. Nothing from an upload is ever `require`d, `import`ed, `eval`ed, run in `vm`,
  spawned, built, or `npm install`ed (so lifecycle scripts never run).
  `apps/api/src/scans/hardening.test.ts` scans a project whose `package.json` scripts,
  `index.js`, config files, ESM module, `eval` call and `node_modules` package would all
  write a marker file if executed, and asserts that none was written. A static check also
  fails the build if the analysis code gains dynamic `require`/`import()`, `vm`,
  `child_process`, `eval` or `new Function`.
- **Isolated, resource-limited analysis.** Profile → parse → detect → remediate runs in a
  `worker_threads` thread:
  - a V8 heap cap (`SCAN_MAX_HEAP_MB`, default 1024)
  - a per-scan wall-clock timeout covering extraction and analysis (`SCAN_TIMEOUT_MS`,
    default 10 min). The thread is **terminated** when it runs out, so even a
    non-yielding loop (e.g. catastrophic regex backtracking) cannot hang the worker.
  - extraction limits: max files, max bytes, compression ratio (see above)

  A runaway scan becomes `failed` with a clear reason (for example "Scan exceeded the 600 s
  time limit and was stopped"). The tests prove both limits with hostile thread entries: an
  infinite loop and a memory bomb.

- **No network assumptions.** Scans need no network. The only outbound calls that exist are
  both **opt-in**: live OSV.dev advisories (`OSV_ADVISORIES=true`) and the remediation LLM
  (`REMEDIATION_LLM=true` plus a key). `OFFLINE=true` forces both off. Inside the analysis
  thread, `fetch` is wrapped in a host allowlist containing only the enabled services, so
  nothing else can be reached through it. To route the opt-in calls through a proxy, use
  Node's `NODE_USE_ENV_PROXY=1` with `HTTPS_PROXY` (Node 22.21+ / 24).
- **Cleanup.** The per-scan temp dir (ZIP copy and extracted tree) is removed when the job
  ends, whatever the outcome. The stored upload is deleted once the scan finishes. A failed
  scan also loses its extracted tree and artifact rows. A completed scan keeps only its
  extracted tree (for the code view) and its reports. Deleting a project removes all of its
  stored files, not just its rows.
- **Nothing is web-served.** `STORAGE_DIR` is never mounted statically. Files are reachable
  only through ownership-checked API routes: source text has secrets redacted, and reports
  are sent with a strict CSP.
- **HTTP abuse limits.**
  - `POST /api/auth/*` (login, register, password reset) is rate-limited per client IP:
    `AUTH_RATE_LIMIT` per 15 minutes, default 30.
  - Uploads are limited per user: `UPLOAD_RATE_LIMIT` per hour, default 30.
  - Over the limit, the API answers `429` with `RateLimit` headers. Behind a proxy, set
    `TRUST_PROXY` so the client IP is used.
- **CORS** allows only the configured frontend origin (`CORS_ORIGIN`, default `APP_BASE_URL`).
  Other origins get no CORS headers.

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
- `sourceFiles` — what to analyze. The [skipped directories](#limits--configuration)
  (`node_modules`, `dist`, `build`, `.git`, …; same list as extraction) are never descended; binaries and files over `ANALYSIS_MAX_FILE_BYTES` (1 MB) are skipped and
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
2. Findings from different detectors on the same file, line, **OWASP category, and weakness**
   (the detector's `cwe`, e.g. `CWE-89`) merge into one correlated finding. It keeps the highest
   severity, combines confidence with noisy-OR (`1 − Π(1 − cᵢ)`, so agreement raises
   confidence), and lists every detector in `contributingDetectors`. Different categories or
   weaknesses on the same line stay separate. This matters in OWASP 2025, where SQLi, NoSQLi,
   SSTI, and XSS all fall under A05 Injection but need different fixes.

**Self-registering registry.** A detector module calls `registerDetector({...})` and is
imported once from `detectors/index.ts`. The engine never changes. `example-todo-comment`
(pattern, `info`, confidence 1.0) flags `TODO SECURITY` comments and serves as a template.

## Detectors

Categories follow the **OWASP Top 10:2025**. Confidence bands: high ≥ 0.8, medium ≥ 0.5.

| ID                           | Detects                                                                                    | OWASP                                                          | Technique                   | Juice Shop challenges   |
| ---------------------------- | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------- | --------------------------- | ----------------------- |
| `A1-sql-injection`           | SQL injection                                                                              | A05:2025 – Injection                                           | dataflow                    | #1–#7                   |
| `A2-nosql-injection`         | NoSQL operator / `$where` injection                                                        | A05:2025 – Injection                                           | dataflow                    | #8–#10                  |
| `A3-ssti`                    | SSTI / dynamic code evaluation                                                             | A05:2025 – Injection                                           | dataflow                    | #11                     |
| `A4-xss`                     | Cross-site scripting: DOM / reflected / stored                                             | A05:2025 – Injection (CWE-79)                                  | dataflow + AST              | #26–#30                 |
| `A5-hardcoded-secrets`       | Hard-coded secrets (keys, tokens, passwords)                                               | A04:2025 – Cryptographic Failures (CWE-798)                    | pattern                     | #14                     |
| `A6-weak-crypto`             | Weak crypto: broken algorithms, unsalted password hashing, encoding-as-encryption          | A04:2025 – Cryptographic Failures (CWE-327/916/261)            | AST + pattern               | #39, #40                |
| `A8-broken-access-control`   | Missing authorization on sensitive routes; IDOR (candidates)                               | A01:2025 – Broken Access Control (CWE-862/639)                 | AST + dataflow (RouteTable) | #20, #21, #22, #24      |
| `A9-mass-assignment`         | Mass assignment; client-chosen field selection                                             | A01:2025 – Broken Access Control (CWE-915/213)                 | AST + dataflow              | #13, #23, #30           |
| `A10-missing-csrf`           | Cookie-authenticated state changes without CSRF protection                                 | A01:2025 – Broken Access Control (CWE-352)                     | config (RouteTable)         | #25                     |
| `A7-sensitive-file-exposure` | Backups/keys/dumps/confidential files in served dirs; listing; suffix-filter bypass; JSONP | A02:2025 – Security Misconfiguration (CWE-538/548/22)          | config                      | #12, #16, #18, #19, #38 |
| `A11-vulnerable-deps`        | Vulnerable, EOL, and typosquatted dependencies                                             | A03:2025 – Software Supply Chain Failures (CWE-1395/1104/1357) | dependency                  | #31, #32                |
| `A12-security-misconfig`     | Verbose errors, missing security headers, listing, deprecated routes, no security.txt      | A02:2025 – Security Misconfiguration (CWE-209/693/548/912)     | AST + config                | #35, #36, #37           |

**A1 — SQL injection.** Sinks: `sequelize.query`, `knex.raw`, Prisma `$queryRawUnsafe` /
`$executeRawUnsafe`, `db.run/all/get/each/exec`, and `*.query` / `*.execute` when the text looks
like SQL. Flags query strings built with `+` or `${}` whose parts taint-trace to
`req.body/query/params/headers/…`. **Critical, 0.9** when request input reaches the query;
**0.6** through an unknown function call; **high, 0.5** when the string is dynamic but no source
can be proven in-file. Not flagged: parameterized queries (`$1` / `?` / `:name` with `bind` or
`replacements`), constant/enum/`process.env`-only strings, `Number()`/`escape()`d values, and
ORM/query-builder calls.

**A2 — NoSQL injection.** Sinks: `find*`, `update*`, `remove`, `delete*`, `count*`,
`replaceOne` on collections/models, `$where`, and `mapReduce`. Flags a request object used as the
whole selector (`update(req.body, …)`) and selector fields taken from the body/query without
scalar coercion (`{ _id: req.body.id }`, which accepts `{"$ne": -1}`): **high, 0.6 (medium)**,
because exploitability depends on body parsing and field types. `$where` / `mapReduce` with
tainted strings: **critical, 0.8**. Not flagged: `String()`/`Number()`/template-coerced values,
`req.params` equality (always strings), `Array#find(fn)`.

**A3 — SSTI / code evaluation.** Sinks: `eval`, `Function`, string `setTimeout`/`setInterval`,
`vm.runIn*` / `vm.Script`, and template engines compiling a template **string**
(`pug.compile`, `ejs.render`, `handlebars.compile`, `_.template`, `nunjucks.renderString`, …).
Sources: request input and user profile fields read back from a user object (`user.username`,
second-order input). **Critical**: 0.95 for request input, 0.85 for a profile field, 0.6 through
a call. `eval` over an untraceable dynamic value: high, 0.4 (low). Not flagged: constant
`eval('2+2')`, `vm` sandboxes and file-based templates without user input, `setTimeout(fn)`.

**A4 — Cross-site scripting.** All findings are **high** severity, and each one is classified
in its evidence and explanation:

- **DOM**: browser code writes URL-controlled data (`location.*`, Angular route params) to an
  HTML sink: `innerHTML`/`outerHTML =`, `document.write`, `insertAdjacentHTML`, `$(…).html()`,
  Angular `bypassSecurityTrust*`, React `dangerouslySetInnerHTML`. Juice Shop #26/#27: search
  param → `bypassSecurityTrustHtml` → `[innerHTML]`.
- **Reflected**: request input echoed by `res.send/write/end` as HTML, or URL data that
  round-trips through a service response (`.subscribe(res => …)`) into an HTML sink. Juice Shop
  #28: track-order id.
- **Stored**: request input saved unsanitised to a renderable model field (`description`,
  `email`, `comment`, …) via `create/update/insert…`, correlated by field name with the place
  it renders unsafely, plus the render side itself. Juice Shop #29: product description via the
  API. #30: an email that is validated only in the browser and rendered in the admin list.

Confidence: **0.85** for proven direct taint, **0.8** for a stored write with a matching unsafe
render site (0.4 if none exists in the project), **0.6** through an unknown call, and
**0.5 (medium)** for an HTML sink with a plausible but unproven source. Not flagged:
auto-escaping bindings (`{{ value }}`, React `{value}`, Angular `[innerHTML]` without a bypass,
since Angular sanitizes it), `textContent`, `DOMPurify.sanitize` / sanitize-html / escape-html /
Angular `sanitizer.sanitize()`, JSON responses, numeric output, and `res.send(render(locals))`.

**A5 — Hardcoded secrets.** Scans every profiled text file plus committed `.env*` / key files
(not tests, fixtures, mocks, or lockfiles) for:

- known key formats: AWS access key IDs and secret keys, Google API keys, Slack tokens and
  webhooks, GitHub / npm / Stripe / SendGrid tokens, JWTs, PEM private keys, and passwords in
  connection URLs
- credential assignments with a literal (`password = '…'`, `{ apiKey: '…' }`, class fields,
  `KEY=value` lines) and literal keys passed to `createHmac`, `createCipheriv`,
  `jwt.sign/verify`, `cookieParser`
- high-entropy strings: Shannon entropy ≥ 4.5 bits/char (hex ≥ 3.5), length ≥ 20, all tunable
  via `createSecretsDetector()`

**Critical** when the file is client-side (served/static dir, front-end source, component files,
or Angular/React/Vue imports), because the secret ships to every browser. The Juice Shop #14
testing password in the Angular login component is this case. Otherwise **high**. Confidence:
0.95 private keys, ~0.9 vendor formats, 0.85 literal crypto/JWT keys, 0.75 credential
assignments, 0.45 entropy-only. Not flagged: placeholders (`changeme`, `xxx`, `your-key-here`,
`example`, `${VAR}`), `process.env`, public/publishable keys, OAuth client IDs, i18n keys, prose,
URLs, file paths, and UUID / hash-shaped strings outside a credential context. **Values are
redacted** in evidence and snippets (`AKIA…[redacted, 20 chars]`; PEM bodies are elided). The
secrets test fixture is generated at test time from split strings, so no complete
provider-format token is committed.

**A6 — Weak cryptography.**

- **Password hashing** with a fast, unsalted hash (`createHash` with any algorithm, `md5()`,
  `CryptoJS.MD5`, …) when the input traces to a password-like value. The trace covers the same
  function and, one level up, the call sites of the hashing helper in files that import it.
  **High.** Juice Shop #39: `security.hash(req.body.password)` → MD5.
- **Broken ciphers**: `createCipher()`, DES / 3DES / RC4 / RC2 / Blowfish, ECB mode, CryptoJS
  DES/RC4/ECB. **High.**
- **Encoding as encryption**: base64 / hex / z85 / rot13 / `btoa` / `atob` inside `encrypt` /
  `decrypt` / `cipher` / `coupon` functions or assigned to `encrypted*`. **Medium.** Juice Shop
  #40: z85 "encrypted" coupons.
- **Other languages**: a pattern rule for `hashlib.md5`, `MessageDigest.getInstance("MD5")`, and
  PHP `md5($…)` on password-handling lines. **High.**
- MD5/SHA-1 off the secret path: checksums, ETags, cache keys, and file digests are dropped;
  other uses are reported as **low** (0.3). bcrypt, argon2, scrypt, and pbkdf2 are never
  flagged.

**RouteTable** (`getRouteTable(ctx)` in `packages/analysis/src/routes`). It is built once per
scan from the ASTs and shared by A8–A10. For Express-style apps/routers
(`app.get/post/…`, `router.route(path).get(…)`) and NestJS controllers (`@Controller` +
`@Get/@Post/…`, `@UseGuards`), each entry is
`{ method, path, middlewareChain, handlerNode, authMechanism }`:

- The middleware chain includes route middleware, earlier `app.use(...)` middleware for that
  path, router mounts (`app.use('/api', auth, router)`), and Nest class guards. Session /
  body-parser setup is marked as infrastructure, not auth.
- Handlers resolve through Juice Shop-style factories (`retrieveBasket()` → the returned
  `(req, res) => …`).
- `authMechanism` is `bearer`, `cookie-session`, or `none`, inferred from the middleware (JWT
  / `isAuthorized` vs session / `requireLogin`) and, failing that, from the handler
  (`req.cookies.token`, `req.session`, `Authorization` header).

**A8 — Broken access control / IDOR.** Severity **high**, confidence **0.5–0.6 (medium)**.
Findings are labelled "Candidate … confirm manually", because authorization intent is semantic.

- **Missing authorization**: PUT/PATCH/DELETE and admin/config/accounting routes with no
  authentication middleware and no auth check in the handler. The evidence notes when the
  matching front-end route is guarded only client-side (`canActivate`). Juice Shop #20, #22.
  Authenticated admin routes without a role check get 0.5.
- **IDOR** on authenticated routes: `findByPk(req.params.id)`, `findOne({ where: { id } })`,
  `destroy/update/delete` keyed by a client id (`req.params/query/body`, Nest `@Param`) with
  no ownership predicate (`UserId: req.user.id`) or owner comparison. Also writes that set a
  client-supplied owned foreign key (`BasketId: req.body.BasketId`). Juice Shop #21, #24.
  Routes behind a role guard are skipped.

**A9 — Mass assignment / over-selection.** Severity **high**.

- **Mass assignment**: the whole body is written (`create(req.body)`, `{ ...req.body }`,
  `Object.assign(user, req.body)`). Confidence **0.85** when the model definition
  (Sequelize `define`/`init`, class fields, Mongoose schema) has privileged fields (role,
  isAdmin, UserId, price, …), **0.55** otherwise. Juice Shop #23 (client-set UserId), #30.
- **Over-selection**: `attributes` / `select` / `projection` / `fields` taken from the client
  (`attributes: req.query.fields.split(',')`). Confidence **0.8** when the model has sensitive
  columns such as the password hash. Juice Shop #13.
- Not flagged: `pick(req.body, [...])` and explicit fields, bodies validated upstream
  (zod/joi/celebrate/express-validator middleware or `schema.parse(req.body)`), and Nest `@Body()`
  DTOs.

**A10 — Missing CSRF protection.** Severity **medium**. Flags state-changing routes
authenticated by a cookie (session middleware, `req.session`, or a token read from
`req.cookies`) with no CSRF middleware (csurf / lusca / csrf-csrf, on the route or via
`app.use`) whose cookie lacks `SameSite=Lax/Strict` (session config or `res.cookie` options).
Confidence 0.7 for session middleware, 0.6 when inferred from the handler. Juice Shop #25.
Bearer-token APIs are excluded.

**A7 — Sensitive / backup file exposure.**

- **Served roots** come from `express.static` / `serveStatic` / `serveIndex`, file-serving
  routes (`res.sendFile(path.resolve('ftp/', file))`), and the profiler's static dirs
  (public/, static/, …).
- **Inside a served root**, backups (`*.bak`, `*.old`, …), dumps, IaC, `.env*`, keys, credential
  stores (`*.kdbx`), VCS metadata, and confidential-looking documents are flagged as **high**,
  located at the exposed file. Juice Shop #12, #16, #18, #38.
- **Directory listing** is **medium** and correlates with A12.
- **Suffix-only type filters** (`endsWith('.md')`) on file-serving routes are **high**: a null
  byte (`%2500.md`) or a double extension bypasses them. #38.
- **JSONP endpoints** (`res.jsonp`) are best effort, at confidence 0.35. #19.

**A11 — Vulnerable & typosquatted dependencies.**

- The resolved dependency set (direct + transitive) is read from `package.json` and
  package-lock (v1–v3) / yarn / pnpm lockfiles. Lockfile versions are exact (0.9). Without a
  lockfile, a range is checked at its minimum version (0.7).
- Advisories come from pluggable **`AdvisorySource`s**. The default is the bundled offline
  snapshot (a small curated sample: sanitize-html, express-jwt, jsonwebtoken, lodash,
  minimist, moment, plus EOL `request` / `marsdb`). It works without network access.
  Setting `OSV_ADVISORIES=true` also queries OSV.dev's batch API, which is opt-in and
  disabled by `OFFLINE=true`. Matches are reported as `high` with no fixed version, and a
  lookup failure becomes a warning, never a failed scan. Juice Shop #31.
- **Typosquats**: a dependency 1–2 edits from a bundled popular-package list, or equal to one
  after stripping a `-js` / `node-` affix, that isn't popular itself or on the verified
  allowlist (e.g. `preact`). The finding names the likely intended package. #32: `epilogue-js`
  → `epilogue`, `ngy-cookie` → `ngx-cookie`.

**A12 — Security misconfiguration.**

- **Verbose errors**: error handlers sending `err.stack` / the raw error, and `errorhandler()`.
  **High**. Suppressed when gated behind a `NODE_ENV` / environment check. #36.
- **Missing security headers** (no `helmet()`, CSP, HSTS, `X-Content-Type-Options`):
  **medium**, at 0.6.
- **Directory listing** and **deprecated/legacy routes** still mounted, including an upload
  route that still parses XML (with an XXE note when `noent: true`): medium, low confidence. #37.
- **No `/.well-known/security.txt`**: a **low** hygiene note. #35.
- Proxy/CDN/deploy-layer configuration is invisible to source analysis, and the explanations
  say so.

**Informational notes.** Documented challenges that aren't code defects detectable from source
are listed in every scan summary (`summary_json.informationalNotes`) as "review manually"
items instead of being dropped: #15 weak password policy, #17 information disclosure in
published content, and #33/#34 discovery.

**Taint tracing** (`traceTaint` in `packages/analysis`) is intra-procedural. It follows
variables through assignments, reassignments, destructuring, `for…of`, and closures, plus
class fields (`this.x` assigned in any method), callback parameters (`.subscribe(v => …)`,
`.then(v => …)`), and string building (`+`, templates, `?:`, `||`/`??`, string methods).
Numeric casts, comparisons, `.length`, and DB lookups (`findByPk(id)` returns stored data, not
`id`) stop taint. Detectors can add sanitizers or treat scalar coercion as safe. Not followed:
calls into other functions or files, object mutation and aliasing, and per-branch control flow.

## What WebGuard can and cannot detect

WebGuard reads source code. That makes it good at **code-level** defects and blind to
**runtime and deployment** behavior. Every finding carries a confidence, and heuristic results
are labeled **Candidate** or **Needs review** in the UI and reports.

**Reliable (static).** High confidence when the source → sink flow is proven within a file:

- SQL and NoSQL injection, SSTI and `eval`
- DOM and reflected XSS with a traceable source
- hardcoded secrets in known formats
- weak password hashing and broken ciphers
- vulnerable and end-of-life dependencies (exact versions come from lockfiles), and typosquats
- stack-trace disclosure, directory listing, and backup or key files in served directories

**Partial (heuristic).** Medium or low confidence, often labeled **Candidate**:

- stored XSS (where data is written is matched to where it is rendered by field name)
- missing authorization and IDOR, mass assignment, CSRF
- missing security headers, entropy-only secrets, JSONP, deprecated routes

Authorization intent is semantic, so confirm these manually. Taint tracing also stays within
one function: flows through helper functions or across files are reported with lower
confidence, or missed.

**Needs dynamic or manual testing.** These appear as **informational notes** in every scan
instead of being dropped; check them with a DAST tool or a manual review:

- weak password policy (#15), information disclosure in published content (#17), and the
  discovery challenges (#33/#34)
- business-logic flaws, race conditions, and authentication flows at runtime
- proxy, CDN, TLS and header configuration that lives outside the code
- secrets stored elsewhere, and vulnerabilities in compiled or minified bundles

**Out of scope.** Languages other than JS/TS (Python, PHP and Java get only pattern rules for
weak hashing), binaries, infrastructure-as-code policy checks, and advisories beyond the
bundled snapshot when OSV is off. The parser layer is pluggable; see
[CONTRIBUTING.md](CONTRIBUTING.md).

A clean scan is not proof of security, and a finding is not proof of exploitability. Treat
WebGuard as a fast, explainable first pass next to code review and dynamic testing.

## Remediation

Every finding is enriched by the remediation engine (`RemediationService` in
`packages/analysis/src/remediation`) after detection and de-duplication, and before
persistence. The result is stored in `findings.remediation_json` (next to the short
`fix_suggestion`) and returned by `GET /api/findings/:id` and `GET /api/scans/:id/findings`:

```ts
{ templateId, title, why, impact, steps: string[], references: [{ title, url }],
  secureExample: { language, before, after, contextualized, note? },
  generatedBy: 'template' | 'template+context' | 'llm' }
```

- **Per-detector fix templates** for all twelve detectors (plus the example detector). Each has
  a title, why/impact, a numbered remediation algorithm, a secure before/after pair, and OWASP
  Cheat Sheet references. Variants are picked by CWE or finding kind (e.g. A4 DOM / reflected /
  stored, A6 password / cipher / encoding, A11 vulnerable / EOL / typosquat). Detectors without
  a template get a generic remediation built from their own explanation and fix text, so no
  finding ships without one.
- **Contextualized secure examples**: the engine rewrites the finding's own code when it can do
  so faithfully:
  - A1 turns concatenated/interpolated SQL into a parameterized call with the same table, fields,
    and expressions (`$n` + `bind` for Sequelize, `$n` for pg, `?` for mysql/sqlite/knex), keeping
    `LIKE` wildcards in the bound value.
  - A4 switches `innerHTML` to `textContent`, `bypassSecurityTrust*` to `sanitize()`, and wraps
    echoed values in `escapeHtml(…)`.
  - A5 replaces the redacted literal with `process.env.NAME`.
  - A6 swaps MD5/SHA password hashing for `argon2.hash` (JS) or `PasswordHasher` (Python).
  - A8 adds the ownership predicate; A9 adds an allowlist; A11 bumps the version or adds an
    `overrides` entry.

  When a safe rewrite isn't possible, the template's generic example is used.

- **Optional LLM assist (off by default)**: with `REMEDIATION_LLM=true` and `ANTHROPIC_API_KEY`
  set, a provider behind the `RemediationLlmProvider` interface drafts an `after` snippet only
  for findings the deterministic rewrites couldn't handle (at most 20 per scan; marked
  `generatedBy: 'llm'` with a "review before applying" note). It sends only the already-redacted
  flagged snippet and the template guidance, never whole files. Without the flag, nothing leaves
  the server, and the templates alone produce complete remediation.

## Reports

**Rollup & risk grade.** When a scan completes, the worker computes the rollup from the
findings it just persisted, in the same transaction, and stores it as `summary_json.rollup`.
The dashboard and every report read these same numbers. The rollup holds counts by severity
and OWASP category, the total, `weightedRisk`, `riskScore` and `grade`:

```
weightedRisk = Σ weight(severity) × confidence     weights: critical 10, high 5, medium 2, low 0.5, info 0
riskScore    = round(100 × (1 − e^(−weightedRisk / 25)))
grade        = A < 10 ≤ B < 25 ≤ C < 50 ≤ D < 75 ≤ F
```

Any critical finding with confidence ≥ 0.8 caps the grade at D (never better), and
`gradeReason` explains the result.

**Exports** (all require `Authorization: Bearer`; other users' scans → 404; unfinished scans → 409):

| Endpoint                         | Returns                                                                                                                                                                                                                                                    |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /api/scans/:id/report.json` | The full `ScanReport`: project, scan, profile summary, rollup, every finding (file:line, snippet, OWASP, CWE, severity, confidence, evidence, explanation, remediation), the informational notes (#15/#17/#33/#34), and detector errors. Machine-readable. |
| `GET /api/scans/:id/report.html` | Self-contained HTML: inline CSS, no scripts, no external assets (CSP `default-src 'none'`). Shows the grade, severity summary, OWASP table, and each finding with an HTML-escaped, syntax-highlighted snippet and its fix.                                 |
| `GET /api/scans/:id/report.pdf`  | The same report as PDF. Streams the stored file, which is recorded as a `report` artifact.                                                                                                                                                                 |

PDFs are rendered by the **worker**, never on the request thread. The worker pre-renders one
when a scan completes (`REPORT_PDF_ON_COMPLETE`). If none exists yet, the endpoint queues a
`report-pdf` job and waits up to `REPORT_PDF_WAIT_MS`, answering `202` with `Retry-After` if the
worker is still busy. Rendering uses the **preinstalled** Chromium/Chrome via
`--headless --no-sandbox --print-to-pdf`, located by `CHROMIUM_PATH` or common install paths;
no browser is downloaded at runtime.

### Source file endpoint

`GET /api/scans/:id/file?path=<relative path>` returns one file from the scan's extracted
copy as JSON. It is the single source for the findings file viewer and the finding detail code
view.

```json
{
  "path": "server.js",
  "language": "javascript",
  "size": 1834,
  "lineCount": 61,
  "content": "…",
  "truncated": false,
  "binary": false,
  "maxBytes": 2097152
}
```

- **Ownership.** Requires `Authorization: Bearer`. Another user's scan answers `404`, exactly
  like the other scan routes.
- **Path confinement.** `path` must be a clean, `/`-separated path relative to the project
  root. The same rules as the extractor's zip-slip guard apply: no absolute or drive paths,
  no `..`, `.` or empty segments, no backslashes, control characters, `:`, or reserved device
  names. A violation answers `400`. The path is only ever joined onto this scan's own
  `scans/<id>/extracted` prefix, which the storage layer validates again. The file must be a
  regular file whose real path, with symlinks resolved, is still inside the storage root. A
  symlink is never followed, at the path itself or in any directory on it.
- **Size limit.** At most `MAX_VIEW_FILE_KB` (default 2048) is read. For a larger file the
  response has the full `size`, `truncated: true`, and a `content` cut at the last whole line
  within the limit, never the whole file.
- **Text only.** Files with a known binary extension, NUL bytes, or mostly control characters
  return `binary: true` and an empty `content`. `language` is detected from the extension (or
  shebang) and is `null` when unknown.
- **Redaction.** Lines the secrets detector flagged are replaced with their redacted snippet.
- **Missing files.** `404` with `{ error, reason }`, where `reason` is one of:
  - `ignored_dir` (plus `ignoredDir`): the file is in a dependency/build/VCS directory
    (`EXTRACT_IGNORE_DIRS`, or one the scan recorded as skipped), so it was never extracted.
  - `extracted_unavailable`: the scan's extracted copy is gone. Completed scans keep it until
    the project is deleted. A failed scan never keeps one.
  - `not_ready`: the scan is still queued or running.
  - `not_found`: no such file in the scan.

## Frontend

`apps/web` is a React + TypeScript SPA built with Vite, React Router, and TanStack Query.
Charts use Recharts, and the code view uses a locally bundled Monaco (no CDN). The CSS is
hand-written and token-based, with light and dark themes that follow the OS or a choice
saved in Account settings. Every control is a native element and is keyboard-reachable.

```bash
npm run dev --workspace apps/web        # http://localhost:5173 (proxies /api to the API)
npm run build --workspace apps/web      # typecheck + production bundle in apps/web/dist
npm test --workspace apps/web           # Vitest + React Testing Library (mocked API)
npm run e2e --workspace apps/web        # Playwright smoke against the real stack
```

**API access.** The browser calls `VITE_API_BASE_URL`. By default that is empty, meaning the
same origin. In development, the Vite server proxies `/api` to `VITE_API_PROXY_TARGET`
(default `http://localhost:$PORT`), so no CORS setup is needed. Both are read from the
repo-root `.env`.

**Auth.** The JWT is kept in memory and mirrored to `localStorage`, so a reload restores the
session after validating it with `GET /api/auth/me`. Every request sends
`Authorization: Bearer <token>`. Any `401` ends the session and the route guard returns to
`/login`, which then sends you back to the page you were on. Forgot-password emails a
single-use link that expires in 30 minutes. In development the link is printed to the API
log, because no mail transport is configured.

| Route                   | What it shows                                                                                                                                                                                                                             |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/login`, `/register`   | Sign in and create an account                                                                                                                                                                                                             |
| `/forgot-password`      | Request a reset link. The response is the same whether or not the account exists                                                                                                                                                          |
| `/reset-password`       | Set a new password from the emailed link                                                                                                                                                                                                  |
| `/projects`             | Project cards showing the last scan's grade, status, and critical/high/medium counts. Create, rename, and delete projects here                                                                                                            |
| `/projects/:id`         | Drag-and-drop ZIP upload with a progress bar, plus the scan history                                                                                                                                                                       |
| `/projects/:id/history` | Risk score over time (line chart with a table view) and a two-scan comparison: pick a baseline and a scan, then see the New / Fixed / Still open findings and the risk delta. "See what changed →" on a scan's trend tile opens it        |
| `/scans/:id`            | Live status, polled every 2 s (queued → running → completed/failed). Once completed: a dashboard (total, risk grade, trend vs the previous scan, severity donut, OWASP bars), report buttons, the findings table, and informational notes |
| `/findings/:id`         | Monaco view of the file with the vulnerable lines highlighted. Explanation / Exploit & Impact / Fix tabs; Fix lists the steps and a before/after with a copy button                                                                       |
| `/scans/:id/report`     | The HTML report in a sandboxed iframe, plus PDF and JSON downloads                                                                                                                                                                        |
| `/account`              | Email, theme, and sign out                                                                                                                                                                                                                |

- **Severity and confidence are always shown.** Findings with low confidence (< 50%) are
  labeled **Needs review**. Route-level heuristics are labeled **Candidate**. Both kinds of
  row are tinted in the findings table.
- **Findings table filters** cover severity, OWASP category, minimum confidence, and file
  path. Results are sorted by severity, with confidence and location as alternative sorts.
  Filters are kept in the URL.
- **Informational notes** (e.g. Juice Shop #15/#17/#33/#34) appear in a separate, distinctly
  styled section. They are not findings and have no severity.
- **Charts.** Severity is ordinal, so it uses a single red ramp that is darkest for critical
  in light mode and brightest for critical in dark mode. Both modes were validated for
  monotone lightness and contrast against the surface. The OWASP chart is one series in one
  blue. Every chart has an HTML legend and a **Table** toggle, so no value is only reachable
  through a tooltip.
- **Clickable locations / file viewer.** Every Location cell in the findings table
  (`server.js:13–15`) is a keyboard-focusable button (`aria-label` "Open server.js at line 13").
  It opens a full-file viewer dialog: the file from this scan's extracted copy in Monaco,
  with line numbers and syntax highlighting, scrolled to and highlighting the finding's
  lines. Every other finding in the same file gets a gutter marker and is listed in a side
  panel; picking one moves the highlight to it. The header shows the path, language, size and
  the finding's summary, with a link to the finding's detail page. Escape, the Close button,
  a click outside, or browser Back closes it (the open viewer is the `?view=<findingId>` URL
  parameter), and focus returns to the location. The viewer explains every case where it
  can't show code: a file in an ignored dependency/build directory ("this file wasn't
  scanned"), a scan whose extracted copy is gone, a file truncated at `MAX_VIEW_FILE_KB`
  (including when the flagged lines are past the cut), and a binary file.
- **Code view.** The finding detail page shows the same file, from the same
  `GET /api/scans/:id/file` fetch (one cached query per scan and path), in the same Monaco
  component. Lines flagged by the secrets detector are replaced with their redacted snippet,
  so neither view ever re-exposes a secret.
- **Reports.** Downloads use `fetch` with the Bearer token and are saved from a Blob. The HTML
  report is shown in `<iframe sandbox>` with no scripts and an opaque origin, so its embedded
  code can never run as the app.
- **States.** Every data view has loading, empty, and error states. Long scans never block the
  UI: you can leave the page and come back.

**E2E.** `npm run e2e` (`apps/web/e2e/full-flow.spec.ts`) runs the whole product against the
real stack, in this order:

1. Register, sign out, and sign in again.
2. Create a project and upload the demo ZIP.
3. Poll the scan to completion.
4. Assert the expected OWASP categories and detector hits.
5. Open the SQL injection finding in Monaco, and confirm the secret is redacted in the code
   view.
6. Download the PDF report and check its `%PDF-` header.
7. Rescan and check the comparison (0 new, 0 fixed).
8. Delete the project.

It starts the API (on `E2E_API_PORT`, default 3100), the worker, and Vite unless they are
already running. CI runs it as a separate job after lint, typecheck and the unit and
integration suites. Postgres and Redis must be running, from
`docker compose up -d`. It uses the preinstalled Chromium/Chrome (`CHROMIUM_PATH` or common
install paths) with `--headless --no-sandbox`; Playwright browsers are never downloaded.

## Authentication

All auth endpoints live under `/api/auth` and accept/return JSON.

| Method | Path                        | Body                  | Success                             | Errors                                            |
| ------ | --------------------------- | --------------------- | ----------------------------------- | ------------------------------------------------- |
| POST   | `/api/auth/register`        | `{ email, password }` | `201 { id, email }`                 | `400` invalid input, `409` email taken            |
| POST   | `/api/auth/login`           | `{ email, password }` | `200 { token }`                     | `401` invalid email or password (generic)         |
| GET    | `/api/auth/me`              | —                     | `200 { id, email }`                 | `401` missing/invalid token                       |
| POST   | `/api/auth/forgot-password` | `{ email }`           | `202 { message }` (always the same) | `400` invalid input                               |
| POST   | `/api/auth/reset-password`  | `{ token, password }` | `204`                               | `400` invalid/used/expired token or weak password |

Password reset stores only a SHA-256 hash of the 32-byte token. The token is single-use and
expires after 30 minutes. A successful reset invalidates the user's other outstanding links.
The link points at `APP_BASE_URL/reset-password`.

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

| Table                   | Purpose                                                          | Key columns                                                                                                                                            |
| ----------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `users`                 | Account owners                                                   | `email` (unique), `password_hash`                                                                                                                      |
| `projects`              | A website codebase owned by a user                               | `user_id → users`, `name`                                                                                                                              |
| `scans`                 | One analysis run of a project                                    | `project_id → projects`, `status` (`queued`/`running`/`completed`/`failed`), `started_at`, `finished_at`, `summary_json`                               |
| `findings`              | A detected vulnerability at a file/line                          | `scan_id → scans`, `detector_id`, `owasp_category`, `severity`, `confidence` (0–1), `file_path`, `line_start`, `line_end`, `snippet`, `fix_suggestion` |
| `artifacts`             | Files produced for a scan (uploaded ZIP, extracted tree, report) | `scan_id → scans`, `kind` (`raw_zip`/`extracted`/`report`), `storage_key`                                                                              |
| `password_reset_tokens` | Single-use password reset links                                  | `user_id → users`, `token_hash` (unique, SHA-256), `expires_at`, `used_at`                                                                             |

All foreign keys cascade on delete (deleting a project removes its scans, findings, and
artifacts) and are indexed; `findings` also has a composite index on `(scan_id, severity)`.

### Projects & scans API

All routes require `Authorization: Bearer <token>`. Resources owned by another user return `404`.

| Method | Path                      | Notes                                                                                                                                                      |
| ------ | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| POST   | `/api/projects`           | `{ name }` → `201` project                                                                                                                                 |
| GET    | `/api/projects`           | Current user's projects, newest first, each with `lastScan` (status, rollup)                                                                               |
| GET    | `/api/projects/:id`       | One project                                                                                                                                                |
| PATCH  | `/api/projects/:id`       | `{ name }` → renamed project                                                                                                                               |
| DELETE | `/api/projects/:id`       | `204`; cascades to scans/findings/artifacts                                                                                                                |
| POST   | `/api/projects/:id/scans` | Multipart ZIP upload (field `file`) → `201` queued scan                                                                                                    |
| GET    | `/api/projects/:id/scans` | Scans for a project, newest first                                                                                                                          |
| GET    | `/api/scans/:id`          | One scan with status and summary                                                                                                                           |
| GET    | `/api/scans/:id/findings` | Filters: `severity` (one or comma-separated), `owaspCategory`, `minConfidence`                                                                             |
| GET    | `/api/scans/:id/compare`  | `?against=<scanId>` → `{ scan, against, fixed, new, persisting, summary }`; both scans must be completed and in the same project (`409` / `400` otherwise) |
| GET    | `/api/scans/:id/file`     | `?path=` → one extracted file as JSON (secret lines redacted, path-confined, `MAX_VIEW_FILE_KB` cap); see [Source file endpoint](#source-file-endpoint)    |

`DELETE /api/projects/:id` also removes the project's stored files. `POST /api/auth/*` and
uploads are rate-limited and answer `429` when over the limit (see
[Scanner hardening](#scanner-hardening)).

**Scan comparison.** Two scans are diffed by a stable **fingerprint**: the SHA-256 of
detector id + file path + whitespace-normalized code, or the line range when there is no code.

- A finding whose code only moved lines, or was re-indented, counts as **persisting**, not as
  one fixed plus one new.
- Fingerprints are matched one-to-one, closest line first, so a third copy of the same bug is
  reported as new.
- `summary` adds the deltas in total findings and risk score.

## Configuration

All settings come from environment variables. Locally they're read from the repo-root `.env`;
see `.env.example`.

| Variable                                                             | Default                                 | Purpose                                                                 |
| -------------------------------------------------------------------- | --------------------------------------- | ----------------------------------------------------------------------- |
| `JWT_SECRET`                                                         | (required)                              | HS256 signing secret (tokens expire after 1 h)                          |
| `PORT`                                                               | `3000`                                  | API port                                                                |
| `DATABASE_URL` / `TEST_DATABASE_URL`                                 | —                                       | Postgres for the app / the test suite (name must end in `_test`)        |
| `REDIS_URL` / `SCAN_QUEUE_NAME`                                      | `redis://localhost:6379` / `scans`      | BullMQ connection and queue                                             |
| `STORAGE_DIR`                                                        | `./storage`                             | Local `StorageService` root (relative to `apps/api`); never served      |
| `MAX_UPLOAD_MB` / `UPLOAD_TIMEOUT_MS`                                | 512 / 600000                            | Upload size cap / upload time limit ([details](#limits--configuration)) |
| `MAX_EXTRACTED_FILES` / `MAX_EXTRACTED_MB` / `MAX_COMPRESSION_RATIO` | 100,000 / 2048 MB / 200                 | Zip-bomb limits ([details](#limits--configuration))                     |
| `ANALYSIS_MAX_FILE_BYTES`                                            | 1 MB                                    | Larger files are profiled but not parsed                                |
| `MAX_VIEW_FILE_KB`                                                   | 2048                                    | File viewer cap; larger files return their head with `truncated: true`  |
| `SCAN_TIMEOUT_MS`                                                    | 600000                                  | Wall-clock limit per scan job                                           |
| `SCAN_MAX_HEAP_MB`                                                   | 1024                                    | Heap cap for the analysis thread                                        |
| `OFFLINE`                                                            | `false`                                 | `true` disables every outbound call (overrides the next two)            |
| `OSV_ADVISORIES`                                                     | `false`                                 | Opt-in live OSV.dev dependency advisories                               |
| `REMEDIATION_LLM` / `ANTHROPIC_API_KEY` / `REMEDIATION_LLM_MODEL`    | `false` / — / SDK default               | Opt-in LLM-drafted secure examples                                      |
| `CHROMIUM_PATH`                                                      | auto-detected                           | Preinstalled Chromium/Chrome for PDF reports and e2e                    |
| `REPORT_PDF_WAIT_MS` / `REPORT_PDF_ON_COMPLETE`                      | 60000 / `true`                          | PDF request wait; pre-render on completion                              |
| `APP_BASE_URL`                                                       | `http://localhost:5173`                 | SPA URL (password-reset links, default CORS origin)                     |
| `CORS_ORIGIN`                                                        | `APP_BASE_URL`                          | Comma-separated origins allowed cross-origin                            |
| `TRUST_PROXY`                                                        | unset                                   | Express `trust proxy` value when behind a reverse proxy                 |
| `AUTH_RATE_LIMIT` / `UPLOAD_RATE_LIMIT`                              | 30 per 15 min / 30 per hour             | Abuse limits (per IP / per user)                                        |
| `VITE_API_BASE_URL` / `VITE_API_PROXY_TARGET`                        | same origin / `http://localhost:$PORT`  | SPA API base and Vite dev-proxy target                                  |
| `E2E_API_PORT` / `E2E_BASE_URL`                                      | `3100` / `http://localhost:5173`        | Ports used by `npm run e2e`                                             |
| `DEMO_EMAIL` / `DEMO_PASSWORD`                                       | `demo@webguard.local` / `webguard-demo` | Seeded demo account                                                     |

## Status

- [x] 1. Project scaffold & tooling
- [x] 2. Backend API & JWT authentication
- [x] 3. Projects & scans data model + CRUD
- [x] 4. ZIP upload, safe extraction & job queue
- [x] 5. Project profiler + parser/AST layer
- [x] 6. Detection engine core + detector registry
- [x] 7. Injection detectors (SQLi, NoSQLi, SSTI)
- [x] 8. Cross-Site Scripting detector
- [x] 9. Secrets & weak-crypto detectors
- [x] 10. Access-control & input detectors
- [x] 11. Files, dependencies & misconfig detectors
- [x] 12. Remediation engine
- [x] 13. Report builder (JSON / HTML / PDF)
- [x] 14. Frontend SPA
- [x] 15. History, compare, hardening, docs & demo
