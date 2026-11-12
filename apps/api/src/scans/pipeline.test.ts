import { existsSync } from 'node:fs';
import { readdir, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createDefaultDetectorRegistry,
  DetectorRegistry,
  exampleTodoComment,
  type Detector,
} from '@webguard/analysis';
import type { Finding, OwaspCategory, Scan, ScanSummary, Severity } from '@webguard/core';
import type { Worker } from 'bullmq';
import request from 'supertest';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createUserWithToken, resetDatabase } from '../../test/helpers.js';
import {
  FAKE,
  materializeSecretsProject,
} from '../../../../packages/analysis/test/secrets-project.js';
import { buildZip } from '../../test/zip-writer.js';
import { createApp } from '../app.js';
import { prisma } from '../db.js';
import { processScan } from './process-scan.js';
import { closeScanQueue, createScanWorker, getScanQueue } from './queue.js';
import { getStorage, storageKeys } from './storage.js';

const app = createApp();
const fixture = (name: string) =>
  fileURLToPath(new URL(`../../test/fixtures/${name}`, import.meta.url));

let alice: string;
let bob: string;
let projectId: string;
let worker: Worker | undefined;

beforeEach(async () => {
  await resetDatabase();
  await getScanQueue().obliterate({ force: true });
  await getStorage().deletePrefix('scans');
  alice = (await createUserWithToken('alice@example.com')).auth;
  bob = (await createUserWithToken('bob@example.com')).auth;
  const res = await request(app)
    .post('/api/projects')
    .set('Authorization', alice)
    .send({ name: 'Site' });
  projectId = res.body.id;
});

afterEach(async () => {
  await worker?.close();
  worker = undefined;
});

afterAll(async () => {
  await getScanQueue().obliterate({ force: true });
  await closeScanQueue();
  await prisma.$disconnect();
});

function upload(auth: string, attach: (req: request.Test) => request.Test) {
  return attach(request(app).post(`/api/projects/${projectId}/scans`).set('Authorization', auth));
}

function uploadFixture(name: string, auth = alice) {
  return upload(auth, (req) =>
    req.attach('file', fixture(name), { contentType: 'application/zip' }),
  );
}

async function pollUntilDone(scanId: string, timeoutMs = 15_000): Promise<Scan[]> {
  const seen: Scan[] = [];
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const res = await request(app).get(`/api/scans/${scanId}`).set('Authorization', alice);
    expect(res.status).toBe(200);
    seen.push(res.body);
    if (res.body.status === 'completed' || res.body.status === 'failed') return seen;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`scan ${scanId} did not finish; last status ${seen.at(-1)?.status}`);
}

describe('POST /api/projects/:id/scans (upload)', () => {
  it('accepts a ZIP, stores it as a raw_zip artifact, and queues a job', async () => {
    const res = await uploadFixture('valid-site.zip');
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ projectId, status: 'queued' });

    const artifacts = await prisma.artifact.findMany({ where: { scanId: res.body.id } });
    expect(artifacts).toEqual([
      expect.objectContaining({ kind: 'raw_zip', storageKey: storageKeys.rawZip(res.body.id) }),
    ]);
    const stored = await readFile(
      path.join(process.env.STORAGE_DIR!, 'scans', res.body.id, 'raw.zip'),
    );
    expect(stored.equals(await readFile(fixture('valid-site.zip')))).toBe(true);

    const job = await getScanQueue().getJob(res.body.id);
    expect(job?.data).toEqual({ scanId: res.body.id });
  });

  it('rejects a non-ZIP upload with 400', async () => {
    const res = await upload(alice, (req) =>
      req.attach('file', Buffer.from('hello'), {
        filename: 'notes.txt',
        contentType: 'text/plain',
      }),
    );
    expect(res.status).toBe(400);
    expect(await prisma.scan.count()).toBe(0);
  });

  it('rejects a file named .zip whose content is not a ZIP with 400', async () => {
    const res = await upload(alice, (req) =>
      req.attach('file', Buffer.from('MZ fake executable'), {
        filename: 'site.zip',
        contentType: 'application/zip',
      }),
    );
    expect(res.status).toBe(400);
    expect(await prisma.scan.count()).toBe(0);
  });

  it('rejects a request with no file with 400', async () => {
    const res = await request(app)
      .post(`/api/projects/${projectId}/scans`)
      .set('Authorization', alice);
    expect(res.status).toBe(400);
  });

  it('rejects uploads over the size limit with 413', async () => {
    const previous = process.env.MAX_UPLOAD_MB;
    process.env.MAX_UPLOAD_MB = '0.0001';
    try {
      const res = await uploadFixture('valid-site.zip');
      expect(res.status).toBe(413);
    } finally {
      if (previous === undefined) delete process.env.MAX_UPLOAD_MB;
      else process.env.MAX_UPLOAD_MB = previous;
    }
    expect(await prisma.scan.count()).toBe(0);
  });

  it("returns 404 and stores nothing when uploading to another user's project", async () => {
    const res = await uploadFixture('valid-site.zip', bob);
    expect(res.status).toBe(404);
    expect(await prisma.scan.count()).toBe(0);
    expect(await getStorage().list('scans')).toEqual([]);
  });
});

describe('worker (BullMQ + Redis + Postgres, end to end)', () => {
  it('processes a valid ZIP: queued → running → completed with an extracted tree', async () => {
    const created = await uploadFixture('valid-site.zip');
    const scanId: string = created.body.id;

    // No worker yet: a polling client sees the scan waiting in the queue.
    const before = await request(app).get(`/api/scans/${scanId}`).set('Authorization', alice);
    expect(before.body.status).toBe('queued');

    worker = createScanWorker();
    const seen = await pollUntilDone(scanId);
    const final = seen.at(-1)!;

    expect(final.status).toBe('completed');
    expect(final.startedAt).not.toBeNull(); // it passed through `running`
    expect(final.finishedAt).not.toBeNull();
    expect(new Date(final.startedAt!) <= new Date(final.finishedAt!)).toBe(true);
    expect(final.summary).toMatchObject({
      filesExtracted: 3,
      extractedFiles: 3,
      totalBytes: expect.any(Number),
      skippedEntries: 0,
      skippedDirs: [],
      skippedFileCount: 0,
      filesParsed: 2, // src/app.js, src/lib/util.js
      parseErrors: 0,
      detectors: [
        'example-todo-comment',
        'A5-hardcoded-secrets',
        'A6-weak-crypto',
        'A1-sql-injection',
        'A2-nosql-injection',
        'A3-ssti',
        'A4-xss',
        'A8-broken-access-control',
        'A9-mass-assignment',
        'A11-vulnerable-deps',
        'A10-missing-csrf',
        'A7-sensitive-file-exposure',
        'A12-security-misconfig',
      ],
      findingsTotal: 0,
      detectorErrors: [],
    });
    expect(final.summary?.profile?.languages.map((l) => l.language)).toEqual([
      'javascript',
      'html',
    ]);

    const extracted = await prisma.artifact.findFirst({ where: { scanId, kind: 'extracted' } });
    expect(extracted?.storageKey).toBe(storageKeys.extracted(scanId));
    expect(await getStorage().list(storageKeys.extracted(scanId))).toEqual([
      `scans/${scanId}/extracted/index.html`,
      `scans/${scanId}/extracted/src/app.js`,
      `scans/${scanId}/extracted/src/lib/util.js`,
    ]);
  });

  it('fails a zip-slip archive safely without writing outside the sandbox', async () => {
    const created = await uploadFixture('zip-slip.zip');
    worker = createScanWorker();
    const final = (await pollUntilDone(created.body.id)).at(-1)!;

    expect(final.status).toBe('failed');
    expect(final.summary?.error).toMatch(/unsafe path/i);
    expect(final.finishedAt).not.toBeNull();
    expect(
      await prisma.artifact.count({ where: { scanId: created.body.id, kind: 'extracted' } }),
    ).toBe(0);
    expect(await getStorage().list(storageKeys.extracted(created.body.id))).toEqual([]);
    expect(existsSync(path.join(os.tmpdir(), 'webguard-zip-slip-pwned.txt'))).toBe(false);
  });
});

/** Zips the analysis package's mini-express fixture, plus a node_modules dir to be ignored. */
async function miniExpressZip(): Promise<Buffer> {
  const root = fileURLToPath(
    new URL('../../../../packages/analysis/test/fixtures/mini-express', import.meta.url),
  );
  const entries = (await readdir(root, { recursive: true, withFileTypes: true }))
    .filter((e) => e.isFile())
    .map((e) => path.join(e.parentPath, e.name));
  return buildZip([
    ...(await Promise.all(
      entries.map(async (abs) => ({
        name: path.relative(root, abs).split(path.sep).join('/'),
        data: await readFile(abs),
      })),
    )),
    { name: 'node_modules/express/index.js', data: 'module.exports = () => {};' },
    { name: 'node_modules/express/package.json', data: '{"name":"express"}' },
  ]);
}

describe('processScan analysis inputs (profile + parse)', () => {
  it('profiles the project and parses sources; a broken file does not fail the scan', async () => {
    const zip = await miniExpressZip();
    const res = await upload(alice, (req) =>
      req.attach('file', zip, {
        filename: 'mini-express.zip',
        contentType: 'application/zip',
      }),
    );
    expect(res.status).toBe(201);
    await processScan(res.body.id);

    const scan = await request(app).get(`/api/scans/${res.body.id}`).set('Authorization', alice);
    const summary = (scan.body as Scan).summary!;
    expect(scan.body.status).toBe('completed');

    // Profile
    const profile = summary.profile!;
    expect(profile.frameworks.map((f) => f.name)).toEqual(['Node.js', 'Express']);
    expect(profile.manifests.map((m) => m.path)).toEqual(['package-lock.json', 'package.json']);
    expect(profile.sourceFiles.some((f) => f.path.startsWith('node_modules/'))).toBe(false);
    // node_modules is skipped by the extractor already (so the profiler never sees it), and
    // the skip is reported; the root manifests are still extracted and profiled.
    expect(summary).toMatchObject({ skippedDirs: ['node_modules'], skippedFileCount: 2 });
    expect(profile.ignored.byReason['ignored-dir']).toBe(0);
    expect(profile.sensitivePaths).toEqual(
      expect.arrayContaining([
        { path: 'Dockerfile', category: 'dockerfile' },
        { path: 'docker-compose.yml', category: 'compose' },
      ]),
    );

    // Parse: 5 JS/TS sources, one intentionally broken.
    expect(summary.filesParsed).toBe(4);
    expect(summary.parseErrors).toBe(1);
    expect(summary.parseErrorSamples).toEqual([
      { path: 'src/legacy/broken.js', message: expect.any(String), line: 3, column: 9 },
    ]);
  });
});

describe('processScan detection (detect → de-dup → persist → summary)', () => {
  async function uploadMiniExpress(): Promise<string> {
    const zip = await miniExpressZip();
    const res = await upload(alice, (req) =>
      req.attach('file', zip, { filename: 'mini-express.zip', contentType: 'application/zip' }),
    );
    expect(res.status).toBe(201);
    return res.body.id;
  }

  it('persists findings and serves them from GET /api/scans/:id/findings', async () => {
    const scanId = await uploadMiniExpress();
    await processScan(scanId);

    const res = await request(app).get(`/api/scans/${scanId}/findings`).set('Authorization', alice);
    expect(res.status).toBe(200);
    // Ordered by file, then line. widget.js:2 renders `user.name` via innerHTML (A4, stored
    // XSS); users.js:8 is a real SQL injection (A1); users.js:13 is parameterized and not reported.
    expect(res.body).toEqual([
      expect.objectContaining({
        detectorId: 'A4-xss',
        severity: 'high',
        filePath: 'src/client/widget.js',
        lineStart: 2,
      }),
      expect.objectContaining({
        detectorId: 'A1-sql-injection',
        severity: 'critical',
        filePath: 'src/routes/users.js',
        lineStart: 8,
      }),
      expect.objectContaining({
        detectorId: 'A12-security-misconfig',
        severity: 'medium',
        filePath: 'src/server.ts',
        lineStart: 4,
      }),
      expect.objectContaining({
        detectorId: 'A12-security-misconfig',
        severity: 'low',
        filePath: 'src/server.ts',
        lineStart: 8,
      }),
      {
        id: expect.any(String),
        scanId,
        detectorId: 'example-todo-comment',
        owaspCategory: 'A06:2025-Insecure Design',
        severity: 'info',
        confidence: 1,
        filePath: 'src/server.ts',
        lineStart: 10,
        lineEnd: 10,
        snippet: '// TODO SECURITY: add rate limiting to /users before launch',
        explanation: expect.stringContaining('TODO SECURITY'),
        fixSuggestion: expect.any(String),
        contributingDetectors: ['example-todo-comment'],
        evidence: [expect.stringContaining('TODO SECURITY')],
        cwe: 'CWE-546',
        remediation: expect.objectContaining({
          templateId: 'example-todo-comment',
          generatedBy: 'template',
        }),
        createdAt: expect.any(String),
      },
    ]);

    // Filters still work on real rows.
    const filtered = await request(app)
      .get(`/api/scans/${scanId}/findings`)
      .query({ severity: 'info' })
      .set('Authorization', alice);
    expect(filtered.body.map((f: { detectorId: string }) => f.detectorId)).toEqual([
      'example-todo-comment',
    ]);
  });

  it('summary counts match the persisted findings', async () => {
    const scanId = await uploadMiniExpress();
    // Only the example detector plus fakes, so the correlation outcome is fully controlled.
    const registry = new DetectorRegistry([exampleTodoComment]);
    registry.register(fakeDetector('fake-sqli', 'A05:2025-Injection', 'high', [8, 13]));
    registry.register(fakeDetector('fake-sqli-2', 'A05:2025-Injection', 'critical', [8]));
    registry.register(
      fakeDetector('fake-secret', 'A04:2025-Cryptographic Failures', 'medium', [8]),
    );
    await processScan(scanId, { detectors: registry });

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    const summary = scan.summaryJson as ScanSummary;
    const rows = await prisma.finding.findMany({ where: { scanId } });

    // users.js:8 → fake-sqli + fake-sqli-2 correlate (same line, same category);
    // fake-secret stays separate (different category). Plus line 13 and the TODO.
    expect(rows).toHaveLength(4);
    const correlated = rows.find(
      (r) => r.lineStart === 8 && r.owaspCategory === 'A05:2025-Injection',
    );
    expect(correlated).toMatchObject({
      detectorId: 'fake-sqli-2',
      severity: 'critical',
      contributingDetectors: ['fake-sqli-2', 'fake-sqli'],
    });

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const byCategory: Record<string, number> = {};
    for (const r of rows) {
      bySeverity[r.severity]++;
      byCategory[r.owaspCategory] = (byCategory[r.owaspCategory] ?? 0) + 1;
    }
    expect(summary.findingsTotal).toBe(rows.length);
    expect(summary.findingsBySeverity).toEqual(bySeverity);
    expect(summary.findingsByOwaspCategory).toEqual(byCategory);
    expect(summary.findingsBySeverity).toEqual({
      critical: 1,
      high: 1,
      medium: 1,
      low: 0,
      info: 1,
    });
  });

  it('records a throwing detector as a detectorError and still completes the scan', async () => {
    const scanId = await uploadMiniExpress();
    const registry = createDefaultDetectorRegistry();
    registry.register({
      ...fakeDetector('broken-detector', 'A05:2025-Injection', 'high', []),
      run: () => {
        throw new Error('detector bug');
      },
    });
    await processScan(scanId, { detectors: registry });

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    const summary = scan.summaryJson as ScanSummary;
    expect(scan.status).toBe('completed');
    expect(summary.detectorErrors).toEqual([
      { detectorId: 'broken-detector', message: 'threw: detector bug' },
    ]);
    // Stage order: pattern, then ast (A6, then the broken one), then the dataflow detectors.
    expect(summary.detectors).toEqual([
      'example-todo-comment',
      'A5-hardcoded-secrets',
      'A6-weak-crypto',
      'broken-detector',
      'A1-sql-injection',
      'A2-nosql-injection',
      'A3-ssti',
      'A4-xss',
      'A8-broken-access-control',
      'A9-mass-assignment',
      'A11-vulnerable-deps',
      'A10-missing-csrf',
      'A7-sensitive-file-exposure',
      'A12-security-misconfig',
    ]);
    // The healthy detectors' findings are still persisted: TODO, SQLi in users.js, XSS in
    // widget.js, and A12's missing-headers + security.txt notes on server.ts.
    expect(await prisma.finding.count({ where: { scanId } })).toBe(5);
  });
});

/** Uploads one of the analysis package's fixture projects and runs the worker on it. */
async function scanFixture(name: string): Promise<{ scanId: string; findings: Finding[] }> {
  return scanDirectory(
    fileURLToPath(new URL(`../../../../packages/analysis/test/fixtures/${name}`, import.meta.url)),
    name,
  );
}

/** Zips a directory, uploads it, runs the worker, and returns the API's findings. */
async function scanDirectory(
  root: string,
  name: string,
): Promise<{ scanId: string; findings: Finding[] }> {
  const files = (await readdir(root, { recursive: true, withFileTypes: true }))
    .filter((e) => e.isFile())
    .map((e) => path.join(e.parentPath, e.name));
  const zip = buildZip(
    await Promise.all(
      files.map(async (abs) => ({
        name: path.relative(root, abs).split(path.sep).join('/'),
        data: await readFile(abs),
      })),
    ),
  );
  const res = await upload(alice, (req) =>
    req.attach('file', zip, { filename: `${name}.zip`, contentType: 'application/zip' }),
  );
  expect(res.status).toBe(201);
  await processScan(res.body.id);
  const all = await request(app)
    .get(`/api/scans/${res.body.id}/findings`)
    .set('Authorization', alice);
  expect(all.status).toBe(200);
  return { scanId: res.body.id, findings: all.body as Finding[] };
}

const line = (f: Finding) =>
  `${f.detectorId} ${f.severity} ${f.confidence} ${f.filePath}:${f.lineStart}`;

describe('injection detectors through the full pipeline', () => {
  it('persists correctly categorized and scored SQLi / NoSQLi / SSTI findings', async () => {
    const { scanId, findings } = await scanFixture('injection');
    const injection = findings.filter((f) => /^A[123]-/.test(f.detectorId));
    expect(injection.map(line)).toEqual([
      'A2-nosql-injection critical 0.8 routes/nosql/showProductReviews.ts:8',
      'A2-nosql-injection high 0.6 routes/nosql/updateProductReviews.ts:7',
      'A2-nosql-injection high 0.6 routes/nosql/whole-body.js:6',
      'A1-sql-injection critical 0.9 routes/sqli/login.ts:9',
      'A1-sql-injection critical 0.9 routes/sqli/raw-concat.js:8',
      'A1-sql-injection critical 0.9 routes/sqli/search.ts:9',
      'A1-sql-injection high 0.5 routes/sqli/unproven.js:5',
      'A3-ssti critical 0.85 routes/ssti/greeting.js:3',
      'A3-ssti critical 0.85 routes/ssti/userProfile.ts:14',
      'A3-ssti critical 0.85 routes/ssti/userProfile.ts:18',
    ]);
    expect(new Set(injection.map((f) => f.owaspCategory))).toEqual(new Set(['A05:2025-Injection']));
    // A8 also (correctly) reports the unauthenticated PATCH /reviews route in whole-body.js.
    expect(findings.filter((f) => f.detectorId === 'A8-broken-access-control').map(line)).toEqual([
      'A8-broken-access-control high 0.6 routes/nosql/whole-body.js:5',
    ]);
    // A4 additionally reports the unsanitised review `message` writes, at low confidence
    // (nothing in this project renders them as HTML).
    expect(findings.filter((f) => f.detectorId === 'A4-xss').map(line)).toEqual([
      'A4-xss high 0.4 routes/nosql/safe.ts:6',
      'A4-xss high 0.4 routes/nosql/updateProductReviews.ts:7',
    ]);

    // High-confidence critical findings via the API filters.
    const critical = await request(app)
      .get(`/api/scans/${scanId}/findings`)
      .query({ severity: 'critical', minConfidence: '0.85' })
      .set('Authorization', alice);
    expect(critical.body).toHaveLength(6);

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    expect((scan.summaryJson as ScanSummary).findingsBySeverity).toEqual({
      critical: 7,
      high: 6, // 2 NoSQLi + unproven SQLi + 2 low-confidence stored XSS + 1 A8 route
      medium: 0,
      low: 0,
      info: 0,
    });
  });
});

describe('XSS detector through the full pipeline', () => {
  it('persists DOM / reflected / stored XSS findings as high severity, and none for safe code', async () => {
    const { findings } = await scanFixture('xss');
    const xss = findings.filter((f) => f.detectorId === 'A4-xss');
    const cls = (f: Finding) => /^(DOM|Reflected|Stored) XSS/.exec(f.evidence[0] ?? '')?.[1];
    expect(xss.map((f) => `${cls(f)} ${f.severity} ${f.filePath}:${f.lineStart}`)).toEqual([
      'Stored high frontend/administration.component.ts:17',
      'DOM high frontend/Comment.jsx:4',
      'DOM high frontend/search-box.component.ts:19',
      'Stored high frontend/search-result.component.ts:19',
      'DOM high frontend/search-result.component.ts:29',
      'Reflected high frontend/track-result.component.ts:18',
      'Stored high server/routes/register.ts:8',
      'Reflected high server/routes/trackOrder.js:4',
      'Reflected high server/routes/trackOrder.js:11',
      'Stored high server/routes/updateProduct.ts:9',
    ]);
    expect(findings).toHaveLength(xss.length); // no other detector fires on this fixture
    expect(xss.every((f) => f.owaspCategory === 'A05:2025-Injection')).toBe(true);
    expect(xss.find((f) => f.filePath.includes('safe'))).toBeUndefined();
  });
});

function fakeDetector(
  id: string,
  owaspCategory: OwaspCategory,
  severity: Severity,
  lines: number[],
): Detector {
  return {
    id,
    title: id,
    owaspCategory,
    technique: 'ast',
    explanation: `${id} explanation`,
    fixSuggestion: `${id} fix`,
    run: (ctx) =>
      lines.map((line) => ({
        detectorId: id,
        owaspCategory,
        severity,
        confidence: 0.7,
        filePath: 'src/routes/users.js',
        lineStart: line,
        lineEnd: line,
        snippet: ctx.snippet('src/routes/users.js', line),
        evidence: `${id} hit`,
      })),
  };
}

describe('processScan limits', () => {
  async function queuedScanWith(zip: Buffer): Promise<string> {
    const res = await upload(alice, (req) =>
      req.attach('file', zip, { filename: 'site.zip', contentType: 'application/zip' }),
    );
    expect(res.status).toBe(201);
    return res.body.id;
  }

  it('fails the scan when the file-count cap is exceeded', async () => {
    const scanId = await queuedScanWith(
      buildZip(Array.from({ length: 10 }, (_, i) => ({ name: `f${i}.js`, data: '1' }))),
    );
    await expect(processScan(scanId, { limits: { maxFiles: 5 } })).rejects.toThrow();

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    expect(scan.status).toBe('failed');
    expect(scan.summaryJson).toEqual({ error: expect.stringMatching(/too many entries/i) });
  });

  it('fails the scan when the uncompressed-size cap is exceeded', async () => {
    const scanId = await queuedScanWith(buildZip([{ name: 'big.js', data: 'x'.repeat(5000) }]));
    await expect(processScan(scanId, { limits: { maxTotalBytes: 1000 } })).rejects.toThrow();

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    expect(scan.status).toBe('failed');
    expect(scan.summaryJson).toEqual({
      error: expect.stringMatching(/maximum uncompressed size/i),
    });
  });

  it('ignores a scan that is no longer queued (duplicate job)', async () => {
    const scanId = await queuedScanWith(await readFile(fixture('valid-site.zip')));
    await processScan(scanId);
    const first = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    await processScan(scanId);
    const second = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    expect(second).toEqual(first);
  });
});

describe('secrets & weak-crypto detectors through the full pipeline', () => {
  it('persists redacted secret findings with client-bundle severity', async () => {
    const root = await materializeSecretsProject();
    try {
      const { findings } = await scanDirectory(root, 'secrets');
      const secrets = findings.filter((f) => f.detectorId === 'A5-hardcoded-secrets');
      expect(secrets.map((f) => `${f.severity} ${f.filePath}:${f.lineStart}`)).toEqual([
        'high config/.env.production:1',
        'high config/.env.production:3',
        'critical frontend/src/app/login/login.component.ts:6',
        'critical frontend/src/app/upload/aws-upload.service.ts:5',
        'critical public/js/chat-widget.js:1',
        'high server/config/aws.ts:2',
        'high server/config/aws.ts:3',
        'high server/lib/keys.ts:1',
        'high server/lib/keys.ts:2',
      ]);
      expect(secrets.every((f) => f.owaspCategory === 'A04:2025-Cryptographic Failures')).toBe(
        true,
      );
      // Nothing persisted or served by the API contains a full secret.
      const served = JSON.stringify(findings);
      for (const value of Object.values(FAKE)) {
        if (!value.startsWith('-----')) expect(served).not.toContain(value);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('persists weak-crypto findings with the right severities', async () => {
    const { findings } = await scanFixture('crypto');
    const weak = findings.filter((f) => f.detectorId === 'A6-weak-crypto');
    expect(weak.map((f) => `${f.severity} ${f.filePath}:${f.lineStart}`)).toEqual([
      'high legacy/auth.py:6',
      'medium server/lib/encryption.js:3',
      'medium server/lib/encryption.js:7',
      'medium server/lib/encryption.js:10',
      'high server/lib/insecurity.ts:5',
      'medium server/lib/insecurity.ts:10',
      'medium server/lib/insecurity.ts:14',
      'high server/lib/legacy-cipher.js:5',
      'high server/lib/legacy-cipher.js:10',
      'high server/lib/legacy-cipher.js:15',
      'low server/lib/request-id.js:5',
      'high server/routes/changePassword.js:7',
      'high server/routes/changePassword.js:8',
    ]);
    expect(weak.some((f) => f.filePath === 'server/lib/checksum.js')).toBe(false);
    expect(weak.some((f) => f.filePath === 'server/lib/passwords.js')).toBe(false);
  });
});

describe('access-control, mass-assignment & CSRF detectors through the full pipeline', () => {
  it('persists route-level candidate findings with honest confidence', async () => {
    const { findings } = await scanFixture('routes');
    const routeLevel = findings.filter((f) => /^A(8|9|10)-/.test(f.detectorId));
    expect(
      routeLevel.map(
        (f) => `${f.detectorId} ${f.severity} ${f.confidence} ${f.filePath}:${f.lineStart}`,
      ),
    ).toEqual([
      'A8-broken-access-control high 0.6 nest/admin.controller.ts:10',
      'A8-broken-access-control high 0.55 nest/admin.controller.ts:23',
      'A8-broken-access-control high 0.55 routes/basket.ts:8',
      'A8-broken-access-control high 0.55 routes/basket.ts:15',
      'A8-broken-access-control high 0.55 routes/basket.ts:30',
      'A9-mass-assignment high 0.85 routes/feedback.ts:14',
      'A9-mass-assignment high 0.85 routes/users.ts:8',
      'A9-mass-assignment high 0.8 routes/users.ts:32',
      'A8-broken-access-control high 0.6 server.ts:18',
      'A8-broken-access-control high 0.6 server.ts:31',
      'A10-missing-csrf medium 0.6 server.ts:44',
    ]);
    expect(new Set(routeLevel.map((f) => f.owaspCategory))).toEqual(
      new Set(['A01:2025-Broken Access Control']),
    );
    expect(
      routeLevel
        .filter((f) => f.detectorId === 'A8-broken-access-control')
        .every((f) => f.explanation.startsWith('Candidate (confirm manually)')),
    ).toBe(true);
  });
});

describe('file-exposure, dependency & misconfiguration detectors through the full pipeline', () => {
  it('persists exposure + misconfig findings and attaches informational notes', async () => {
    const { scanId, findings } = await scanFixture('exposure');
    const relevant = findings
      .filter((f) => /^A(7|12)-/.test(f.detectorId))
      .map((f) => `${f.detectorId} ${f.severity} ${f.filePath}:${f.lineStart}`);
    expect(relevant).toEqual([
      'A7-sensitive-file-exposure high ftp/acquisitions.md:1',
      'A7-sensitive-file-exposure high ftp/coupons_2013.md.bak:1',
      'A7-sensitive-file-exposure high ftp/incident-support.kdbx:1',
      'A7-sensitive-file-exposure high ftp/package.json.bak:1',
      'A7-sensitive-file-exposure medium routes/currentUser.js:9',
      'A7-sensitive-file-exposure high routes/fileServer.js:18',
      'A12-security-misconfig medium server.js:11',
      'A12-security-misconfig medium server.js:19',
      'A12-security-misconfig medium server.js:26',
      'A12-security-misconfig medium server.js:28',
      'A12-security-misconfig high server.js:31',
      'A12-security-misconfig low server.js:33',
    ]);
    // Directory listing is reported once, correlated across A7 and A12.
    const listing = findings.find((f) => f.filePath === 'server.js' && f.lineStart === 19)!;
    expect([...listing.contributingDetectors].sort()).toEqual([
      'A12-security-misconfig',
      'A7-sensitive-file-exposure',
    ]);

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    const notes = (scan.summaryJson as ScanSummary).informationalNotes!;
    expect(notes.map((n) => n.id)).toEqual([
      'weak-password-policy',
      'information-disclosure',
      'discovery',
    ]);
  });

  it('persists vulnerable and typosquatted dependency findings, offline', async () => {
    const { findings } = await scanFixture('deps');
    const deps = findings
      .filter((f) => f.detectorId === 'A11-vulnerable-deps')
      .map((f) => `${f.severity} ${f.filePath}:${f.lineStart} ${f.evidence[0]!.split(':')[0]}`)
      .sort(); // DB collation orders package.json / package-lock.json differently per locale
    expect(deps).toEqual([
      'critical package-lock.json:23 minimist@1.2.5 (transitive dependency)',
      'high frontend/package.json:6 possible typosquat',
      'high package.json:12 sanitize-html@1.4.2 (direct dependency)',
      'high package.json:6 possible typosquat',
      'high package.json:8 express-jwt@0.1.3 (direct dependency)',
      'medium package.json:11 request@2.88.2 (direct dependency)',
    ]);
    expect(
      findings.every((f) => f.owaspCategory === 'A03:2025-Software Supply Chain Failures'),
    ).toBe(true);
  });
});

describe('remediation through the full pipeline', () => {
  it('persists remediation for every finding and serves it from GET /api/findings/:id', async () => {
    const { findings } = await scanFixture('injection');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.remediation && f.remediation.steps.length > 0)).toBe(true);

    const login = findings.find(
      (f) => f.detectorId === 'A1-sql-injection' && f.filePath === 'routes/sqli/login.ts',
    )!;
    const res = await request(app).get(`/api/findings/${login.id}`).set('Authorization', alice);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ id: login.id, detectorId: 'A1-sql-injection', cwe: 'CWE-89' });
    const r = (res.body as Finding).remediation!;
    expect(r).toMatchObject({
      templateId: 'A1-sql-injection',
      title: 'Use a parameterized query',
      generatedBy: 'template+context',
    });
    expect(r.why).toMatch(/SQL/);
    expect(r.impact).toMatch(/Authentication bypass/);
    expect(r.steps.length).toBeGreaterThanOrEqual(5);
    expect(r.secureExample.after).toContain(
      "'SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL'",
    );
    expect(r.secureExample.after).toContain(
      "bind: [req.body.email || '', security.hash(req.body.password || '')]",
    );
    expect(r.references.map((x) => x.url)).toContain(
      'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
    );
  });

  it("returns 404 for another user's finding and for unknown ids", async () => {
    const { findings } = await scanFixture('injection');
    const id = findings[0]!.id;
    expect((await request(app).get(`/api/findings/${id}`).set('Authorization', bob)).status).toBe(
      404,
    );
    expect(
      (await request(app).get('/api/findings/not-a-uuid').set('Authorization', alice)).status,
    ).toBe(404);
    expect((await request(app).get(`/api/findings/${id}`)).status).toBe(401);
  });

  it('runs without the LLM by default (no flag, no network)', () => {
    expect(process.env.REMEDIATION_LLM).toBeUndefined();
  });
});
