import { existsSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
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
    const previous = process.env.MAX_UPLOAD_BYTES;
    process.env.MAX_UPLOAD_BYTES = '100';
    try {
      const res = await uploadFixture('valid-site.zip');
      expect(res.status).toBe(413);
    } finally {
      if (previous === undefined) delete process.env.MAX_UPLOAD_BYTES;
      else process.env.MAX_UPLOAD_BYTES = previous;
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
      totalBytes: expect.any(Number),
      skippedEntries: 0,
      filesParsed: 2, // src/app.js, src/lib/util.js
      parseErrors: 0,
      detectors: [
        'example-todo-comment',
        'A1-sql-injection',
        'A2-nosql-injection',
        'A3-ssti',
        'A4-xss',
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
    expect(profile.ignored.byReason['ignored-dir']).toBe(2);
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
    // Stage order: pattern, then ast (the broken one), then the dataflow detectors.
    expect(summary.detectors).toEqual([
      'example-todo-comment',
      'broken-detector',
      'A1-sql-injection',
      'A2-nosql-injection',
      'A3-ssti',
      'A4-xss',
    ]);
    // The healthy detectors' findings are still persisted (TODO, SQLi in users.js, XSS in widget.js).
    expect(await prisma.finding.count({ where: { scanId } })).toBe(3);
  });
});

/** Uploads one of the analysis package's fixture projects and runs the worker on it. */
async function scanFixture(name: string): Promise<{ scanId: string; findings: Finding[] }> {
  const root = fileURLToPath(
    new URL(`../../../../packages/analysis/test/fixtures/${name}`, import.meta.url),
  );
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
    expect(new Set(findings.map((f) => f.owaspCategory))).toEqual(new Set(['A05:2025-Injection']));
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
      high: 5,
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
