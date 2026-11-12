# Contributing to WebGuard

Thanks for helping. This guide covers local setup, the ground rules for scanner code, and the
two most common extensions: **a new detector** and **a new language**.

## Setup

```bash
cp .env.example .env          # set JWT_SECRET
npm install
docker compose up -d          # Postgres + Redis
npm run db:migrate
npm run demo -- --setup       # optional: seed the demo user/project
```

Before opening a PR, run everything CI runs:

```bash
npm run lint                  # eslint + prettier --check
npm run typecheck
npm test                      # unit + integration (API tests use the *_test database)
npm run e2e                   # Playwright, preinstalled Chromium (see README → Frontend)
```

## Ground rules for scanner code

WebGuard analyzes **untrusted code**. Anything in `packages/analysis` or the scan pipeline must:

- **Only read.** Never `require`/`import()` a scanned file, `eval` it, run it in `vm`, spawn a
  process on it, or install its dependencies. Use `ctx.readText()` and the parsed AST.
  `apps/api/src/scans/hardening.test.ts` enforces this with a static check and a scan of a
  project whose every entry point would write a marker file if it were executed.
- **Need no network.** Scans run offline by default. Any outbound call must be opt-in behind
  a config flag, respect `OFFLINE=true`, and be added to the analysis thread's host allowlist
  (`allowedHosts()` in `apps/api/src/scans/analyze.ts`). Otherwise the guard refuses it.
- **Stay bounded.** Analysis runs in a worker thread with a heap cap and a wall-clock timeout.
  Still, avoid regexes with catastrophic backtracking on attacker-controlled text. Prefer AST
  queries, and cap loops over files and findings.
- **Never fail the scan.** Throw only for programming errors. The engine records a throwing
  detector as a `detectorError` and continues.
- **Never leak secrets.** Evidence and snippets that contain secret values must be redacted.

## Adding a detector

A detector is a plain object implementing `Detector`
(`packages/analysis/src/detection/types.ts`):

```ts
interface Detector {
  id: string; // "A13-open-redirect"
  title: string;
  owaspCategory: OwaspCategory; // OWASP Top 10:2025
  cwe?: string; // "CWE-601"
  technique: 'pattern' | 'ast' | 'dataflow' | 'dependency' | 'config';
  explanation: string;
  fixSuggestion: string;
  run(ctx: DetectionContext): RawFinding[] | Promise<RawFinding[]>;
}
```

1. **Implement it.** Create `packages/analysis/src/detection/detectors/a13-open-redirect.ts`.
   Copy `example-todo-comment.ts` as a starting point. Use the context instead of the file
   system:
   - `ctx.files` gives parsed files with their ASTs.
   - `findCalls(['res.redirect'])`, `findTagged('source:http-input')` and `traceTaint(...)` are
     the AST and data-flow helpers.
   - `getRouteTable(ctx)` gives Express/Nest routes.
   - `ctx.snippet(path, start, end)` builds code snippets.

   Pick an honest `confidence`: ≥ 0.8 when the source → sink flow is proven, 0.5–0.7 when it is
   plausible, < 0.5 for heuristics. For route-level guesses, prefix the evidence with
   `Candidate`; the UI then labels the finding for manual confirmation.

2. **Register it.** Wrap the object in `registerDetector({...})` and add one import line to
   `packages/analysis/src/detection/detectors/index.ts`. The engine, registry and API need no
   other changes.

3. **Add a fix template.** In `packages/analysis/src/remediation/templates.ts`, add a
   `FixTemplate` with a title, why, impact, numbered steps, a correct vulnerable/secure
   example, and references from `references.ts`. Then add a `TemplateSet` entry to
   `TEMPLATE_SETS` with your `detectorId`:
   - Use `variants` and `select` when one detector covers several weakness classes.
   - Optionally add a `contextualize` function in `contextualize.ts` that rewrites the
     finding's own code. It returns `undefined` when a faithful rewrite isn't possible.

   The remediation tests fail if a built-in detector has no template.

4. **Add fixtures and tests.**
   - Put a small vulnerable project and its safe counterparts under
     `packages/analysis/test/fixtures/<name>/`. Test the safe code too, so false positives
     can't creep in.
   - Add a unit test next to the related detectors in
     `packages/analysis/src/detection/detectors/*.test.ts`. Assert ids, lines, severity,
     confidence and evidence, and that safe files produce nothing.
   - If the finding should show up end to end, extend
     `apps/api/src/scans/pipeline.test.ts`.
   - If it belongs in the demo, add a case to `apps/api/demo/vulnerable-shop.ts` and update
     `DEMO_EXPECTED`. The e2e test asserts it.
   - Generate secret-shaped test data at runtime (see `test/secrets-project.ts`). Never commit
     a complete token format.

5. **Document it.** Add a row to the detector catalog in `README.md`, and update
   "What WebGuard can and cannot detect" if the coverage changes.

## Adding a language

Languages plug in at the parser layer. Detectors work on the common AST
(`AstNode { type, rawType, loc, children, tags, raw }`), so a new language mostly means
mapping its parser's nodes onto that vocabulary.

1. **Implement a `ParserAdapter`** (`packages/analysis/src/parsers/registry.ts`):

   ```ts
   interface ParserAdapter {
     readonly id: string; // "python-lezer"
     readonly languages: readonly Language[]; // ['python']
     parse(input: { path: string; language: Language; sourceText: string }): {
       ast: AstNode | null;
       parseError?: ParseError;
     };
   }
   ```

   Use `babel-adapter.ts` as the reference. Map native nodes to the normalized types (`Call`,
   `MemberAccess`, `Assignment`, `StringLiteral`, `Function`, …), fill 1-based `loc`, set
   resolved names (`db.execute`, `request.args.id`), and keep the native node in `raw`.

   Choose a pure-JS parser (no native or WASM build step, no code execution) that recovers from
   errors. `parse` may throw; the registry turns that into a non-fatal `parseError`.

2. **Make files reach the adapter.** Add the extensions to `detectLanguage()` in
   `packages/analysis/src/profiler/languages.ts`, and the `Language` value to
   `packages/core` if it is new.

3. **Register the adapter** in `createDefaultParserRegistry()`
   (`packages/analysis/src/parse-project.ts`).

4. **Teach taint the new sources and sinks.** Add `TagRule`s for the framework's request
   inputs, for example Flask `request.args` → `source:http-input`. Detectors that query tags and
   `findCalls` then work unchanged. Sinks with different names (`cursor.execute`) are added to
   the relevant detectors.

5. **Test it.** Add parser tests (`src/parsers/parsers.test.ts`) for locations, names and error
   recovery, then fixture-based detector tests for the new language.

## Commits and PRs

Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat(detectors): …`,
`fix(api): …`). Keep PRs focused, include tests, and update the README when behavior or
configuration changes.
