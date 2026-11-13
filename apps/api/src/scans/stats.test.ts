import { DetectorRegistry, type Detector } from '@webguard/analysis';
import type { ProjectStats, ScanStatsResponse } from '@webguard/core';
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { createUserWithToken, resetDatabase } from '../../test/helpers.js';
import { buildZip } from '../../test/zip-writer.js';
import { createApp } from '../app.js';
import { prisma } from '../db.js';
import { processScan } from './process-scan.js';
import { closeScanQueue, getScanQueue } from './queue.js';
import { getStorage } from './storage.js';

const app = createApp();
let alice: string;
let bob: string;
let projectId: string;

beforeEach(async () => {
  await resetDatabase();
  await getScanQueue().obliterate({ force: true });
  await getStorage().deletePrefix('scans');
  alice = (await createUserWithToken('alice@example.com')).auth;
  bob = (await createUserWithToken('bob@example.com')).auth;
  const res = await request(app)
    .post('/api/projects')
    .set('Authorization', alice)
    .send({ name: 'Shop' });
  projectId = res.body.id;
});

afterAll(async () => {
  await getScanQueue().obliterate({ force: true });
  await closeScanQueue();
  await prisma.$disconnect();
});

const SERVER_JS = [
  "const express = require('express');",
  "const mysql = require('mysql2');",
  'const app = express();',
  'const db = mysql.createConnection({});',
  '',
  '// product search',
  "app.get('/p', (req, res) => {",
  "  db.query('SELECT * FROM p WHERE n = ' + req.query.q, (e, rows) => res.json(rows));",
  '});',
  'app.listen(3000);',
  '',
].join('\n');

function projectZip(): Buffer {
  return buildZip([
    {
      name: 'package.json',
      data: JSON.stringify({
        name: 'shop',
        main: 'server.js',
        scripts: { start: 'node server.js' },
        dependencies: { express: '4.17.1', mysql2: '^3.0.0', expresss: '1.0.0' },
      }),
    },
    { name: 'server.js', data: SERVER_JS, deflate: true },
    { name: 'lib/util.py', data: '# helper\n\ndef f():\n    return 1\n' },
    { name: 'public/logo.png', data: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 1]) },
    { name: 'node_modules/express/index.js', data: 'module.exports = {};\n' },
    { name: 'README.md', data: '# Shop\n' },
  ]);
}

async function upload(zip: Buffer, auth = alice): Promise<string> {
  const res = await request(app)
    .post(`/api/projects/${projectId}/scans`)
    .set('Authorization', auth)
    .attach('file', zip, { filename: 'shop.zip', contentType: 'application/zip' });
  expect(res.status).toBe(201);
  return res.body.id as string;
}

const getStats = (scanId: string, auth = alice) =>
  request(app).get(`/api/scans/${scanId}/stats`).set('Authorization', auth);

describe('GET /api/scans/:id/stats', () => {
  it('serves the statistics computed during the scan, aligned with the rollup', async () => {
    const zip = projectZip();
    const scanId = await upload(zip);
    await processScan(scanId);

    const res = await getStats(scanId);
    expect(res.status).toBe(200);
    const body = res.body as ScanStatsResponse;
    expect(body).toMatchObject({ scanId, status: 'completed', error: null });
    const stats = body.stats!;
    expect(stats).toMatchObject({ version: 1, status: 'complete', stage: 'complete' });

    // Size: node_modules was never extracted; lib/ and public/ are the folders.
    expect(stats.size).toMatchObject({
      files: 5,
      folders: 2,
      zipBytes: zip.length,
    });
    expect(stats.size.loc!.total).toBeGreaterThan(10);
    expect(stats.skipped).toMatchObject({ ignoredDirFiles: 1, ignoredDirs: ['node_modules'] });
    expect(stats.skipped.binary).toBe(1);

    // Languages & stack.
    const js = stats.languages.find((l) => l.language === 'javascript')!;
    expect(js).toMatchObject({ files: 1, analysisDepth: 'full-ast' });
    expect(js.loc).toEqual({ code: 8, comment: 1, blank: 1, total: 10 });
    expect(stats.languages.find((l) => l.language === 'python')).toMatchObject({
      analysisDepth: 'pattern-only',
      analysisLabel: 'secrets/crypto/deps/config only',
    });
    expect(stats.stack!.entryPoints[0]).toBe('server.js');
    expect(stats.stack!.frameworks.map((f) => f.name)).toContain('Express');
    expect(stats.stack!.packageManagers).toEqual([{ name: 'npm', lockfile: null }]);

    // Security numbers are the rollup's.
    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    const rollup = (
      scan.summaryJson as { rollup: { grade: string; riskScore: number; total: number } }
    ).rollup;
    expect(stats.security).toMatchObject({
      grade: rollup.grade,
      riskScore: rollup.riskScore,
      total: rollup.total,
    });
    expect(stats.security!.topFiles[0]!.path).toBeDefined();

    // The tree carries the findings, colored by the worst severity.
    const serverNode = stats.tree!.children!.find((c) => c.path === 'server.js')!;
    expect(serverNode.findings).toBeGreaterThan(0);
    expect(serverNode.worstSeverity).toBe('critical');
    expect(stats.tree!.findings).toBe(rollup.total);

    // Dependencies (A11): a typosquat of express, direct deps counted.
    expect(stats.dependencies!.direct).toBe(3);
    expect(stats.dependencies!.typosquats.map((t) => t.name)).toContain('expresss');

    expect(stats.scan.rules).toContain('A1-sql-injection');
    expect(stats.scan.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('returns the stored statistics verbatim (no recomputation on request)', async () => {
    const scanId = await upload(projectZip());
    const sentinel = { version: 1, status: 'complete', marker: 'stored-not-recomputed' };
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'completed', finishedAt: new Date(), statsJson: sentinel },
    });
    const res = await getStats(scanId);
    expect(res.status).toBe(200);
    expect(res.body.stats).toEqual(sentinel);
  });

  it("returns 404 for another user's scan and 401 without a token", async () => {
    const scanId = await upload(projectZip());
    const res = await getStats(scanId, bob);
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Not found' });
    expect((await request(app).get(`/api/scans/${scanId}/stats`)).status).toBe(401);
    expect((await getStats('not-a-uuid')).status).toBe(404);
  });

  it('returns null stats while a scan is queued', async () => {
    const scanId = await upload(projectZip());
    const res = await getStats(scanId);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ scanId, status: 'queued', stats: null, error: null });
  });

  it('keeps partial stats of a scan that failed during extraction', async () => {
    const zip = projectZip();
    const scanId = await upload(zip);
    await expect(processScan(scanId, { limits: { maxFiles: 2 } })).rejects.toThrow();

    const body = (await getStats(scanId)).body as ScanStatsResponse;
    expect(body.status).toBe('failed');
    expect(body.error).toMatch(/too many entries/);
    const stats = body.stats as ProjectStats;
    expect(stats).toMatchObject({ status: 'partial', stage: 'upload' });
    expect(stats.size).toMatchObject({ zipBytes: zip.length, files: null, loc: null });
    expect(stats.tree).toBeNull();
    expect(stats.security).toBeNull();
  });

  it('keeps extraction stats of a scan that failed during analysis', async () => {
    const scanId = await upload(projectZip());
    const hang: Detector = {
      id: 'test-hang',
      title: 'hangs',
      owaspCategory: 'A05:2025-Injection',
      technique: 'pattern',
      explanation: 'x',
      fixSuggestion: 'x',
      run: () => new Promise((resolve) => setTimeout(() => resolve([]), 5000).unref()),
    };
    await expect(
      processScan(scanId, { detectors: new DetectorRegistry([hang]), timeoutMs: 1500 }),
    ).rejects.toThrow(/time limit/);

    const body = (await getStats(scanId)).body as ScanStatsResponse;
    expect(body).toMatchObject({ status: 'failed', error: expect.stringMatching(/time limit/) });
    expect(body.stats).toMatchObject({ status: 'partial', stage: 'extraction' });
    expect(body.stats!.size).toMatchObject({ files: 5 });
    expect(body.stats!.skipped).toMatchObject({ ignoredDirFiles: 1 });
    expect(body.stats!.scan.startedAt).toEqual(expect.any(String));
  });
});
