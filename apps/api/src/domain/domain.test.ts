import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Finding, Project, Scan } from '@webguard/core';
import request from 'supertest';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createUserWithToken, resetDatabase } from '../../test/helpers.js';
import { createApp } from '../app.js';
import { config } from '../config.js';
import { prisma } from '../db.js';
import { closeScanQueue, getScanQueue } from '../scans/queue.js';
import { getStorage, storageKeys } from '../scans/storage.js';

const app = createApp();
let alice: string;
let bob: string;

beforeEach(async () => {
  await resetDatabase();
  alice = (await createUserWithToken('alice@example.com')).auth;
  bob = (await createUserWithToken('bob@example.com')).auth;
});

afterAll(async () => {
  await getScanQueue().obliterate({ force: true });
  await closeScanQueue();
  await prisma.$disconnect();
});

async function createProject(auth: string, name = 'My site'): Promise<Project> {
  const res = await request(app).post('/api/projects').set('Authorization', auth).send({ name });
  expect(res.status).toBe(201);
  return res.body as Project;
}

const validZip = fileURLToPath(new URL('../../test/fixtures/valid-site.zip', import.meta.url));

async function createScan(auth: string, projectId: string): Promise<Scan> {
  const res = await request(app)
    .post(`/api/projects/${projectId}/scans`)
    .set('Authorization', auth)
    .attach('file', validZip, { contentType: 'application/zip' });
  expect(res.status).toBe(201);
  return res.body as Scan;
}

describe('authentication', () => {
  it('requires a token on project and scan routes', async () => {
    expect((await request(app).get('/api/projects')).status).toBe(401);
    expect((await request(app).post('/api/projects').send({ name: 'x' })).status).toBe(401);
    expect((await request(app).get('/api/scans/00000000-0000-0000-0000-000000000000')).status).toBe(
      401,
    );
  });
});

describe('projects CRUD', () => {
  it('creates a project', async () => {
    const project = await createProject(alice, '  Shop frontend  ');
    expect(project).toEqual({
      id: expect.any(String),
      userId: expect.any(String),
      name: 'Shop frontend',
      createdAt: expect.any(String),
    });
  });

  it('rejects an invalid name with 400', async () => {
    const res = await request(app)
      .post('/api/projects')
      .set('Authorization', alice)
      .send({ name: '' });
    expect(res.status).toBe(400);
  });

  it("lists only the current user's projects, newest first", async () => {
    const first = await createProject(alice, 'first');
    const second = await createProject(alice, 'second');
    await createProject(bob, 'bobs');

    const res = await request(app).get('/api/projects').set('Authorization', alice);
    expect(res.status).toBe(200);
    expect(res.body.map((p: Project) => p.id)).toEqual([second.id, first.id]);
  });

  it('gets, renames, and deletes a project', async () => {
    const project = await createProject(alice);

    const got = await request(app).get(`/api/projects/${project.id}`).set('Authorization', alice);
    expect(got.status).toBe(200);
    expect(got.body).toEqual(project);

    const renamed = await request(app)
      .patch(`/api/projects/${project.id}`)
      .set('Authorization', alice)
      .send({ name: 'Renamed' });
    expect(renamed.status).toBe(200);
    expect(renamed.body.name).toBe('Renamed');

    const deleted = await request(app)
      .delete(`/api/projects/${project.id}`)
      .set('Authorization', alice);
    expect(deleted.status).toBe(204);

    const after = await request(app).get(`/api/projects/${project.id}`).set('Authorization', alice);
    expect(after.status).toBe(404);
  });

  it('cascades project deletion to scans and findings', async () => {
    const project = await createProject(alice);
    const scan = await createScan(alice, project.id);
    await prisma.finding.create({ data: findingData(scan.id, {}) });

    await request(app).delete(`/api/projects/${project.id}`).set('Authorization', alice);

    expect(await prisma.scan.count({ where: { id: scan.id } })).toBe(0);
    expect(await prisma.finding.count({ where: { scanId: scan.id } })).toBe(0);
  });

  it('returns 404 for a malformed id', async () => {
    const res = await request(app).get('/api/projects/not-a-uuid').set('Authorization', alice);
    expect(res.status).toBe(404);
  });
});

describe('scans', () => {
  it('creates a queued scan and lists scans for the project', async () => {
    const project = await createProject(alice);
    const scan = await createScan(alice, project.id);
    expect(scan).toMatchObject({
      projectId: project.id,
      status: 'queued',
      startedAt: null,
      finishedAt: null,
      summary: null,
    });

    const second = await createScan(alice, project.id);
    const list = await request(app)
      .get(`/api/projects/${project.id}/scans`)
      .set('Authorization', alice);
    expect(list.status).toBe(200);
    expect(list.body.map((s: Scan) => s.id)).toEqual([second.id, scan.id]);

    const got = await request(app).get(`/api/scans/${scan.id}`).set('Authorization', alice);
    expect(got.status).toBe(200);
    expect(got.body).toEqual(scan);
  });
});

function findingData(
  scanId: string,
  overrides: Partial<{ severity: Finding['severity']; owaspCategory: string; confidence: number }>,
) {
  return {
    scanId,
    detectorId: 'test-detector',
    owaspCategory: 'A05:2025-Injection',
    severity: 'high' as const,
    confidence: 0.9,
    filePath: 'src/index.js',
    lineStart: 1,
    lineEnd: 1,
    snippet: 'eval(input)',
    explanation: 'Untrusted input reaches eval.',
    fixSuggestion: 'Do not eval user input.',
    ...overrides,
  };
}

describe('GET /api/scans/:id/findings', () => {
  async function seedFindings() {
    const project = await createProject(alice);
    const scan = await createScan(alice, project.id);
    await prisma.finding.createMany({
      data: [
        findingData(scan.id, { severity: 'critical', confidence: 0.95 }),
        findingData(scan.id, { severity: 'high', confidence: 0.4 }),
        findingData(scan.id, {
          severity: 'low',
          owaspCategory: 'A02:2025-Security Misconfiguration',
          confidence: 0.7,
        }),
      ],
    });
    return scan;
  }

  async function getFindings(scanId: string, query: Record<string, string> = {}) {
    return request(app)
      .get(`/api/scans/${scanId}/findings`)
      .query(query)
      .set('Authorization', alice);
  }

  it('returns all findings without filters', async () => {
    const scan = await seedFindings();
    const res = await getFindings(scan.id);
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(3);
    expect(res.body[0]).toMatchObject({ scanId: scan.id, detectorId: 'test-detector' });
  });

  it('filters by severity (single and comma-separated)', async () => {
    const scan = await seedFindings();
    const single = await getFindings(scan.id, { severity: 'critical' });
    expect(single.body.map((f: Finding) => f.severity)).toEqual(['critical']);

    const multi = await getFindings(scan.id, { severity: 'critical,low' });
    expect(multi.body.map((f: Finding) => f.severity).sort()).toEqual(['critical', 'low']);
  });

  it('filters by owaspCategory', async () => {
    const scan = await seedFindings();
    const res = await getFindings(scan.id, { owaspCategory: 'A02:2025-Security Misconfiguration' });
    expect(res.body.map((f: Finding) => f.severity)).toEqual(['low']);
  });

  it('filters by minConfidence', async () => {
    const scan = await seedFindings();
    const res = await getFindings(scan.id, { minConfidence: '0.7' });
    expect(res.body.map((f: Finding) => f.severity).sort()).toEqual(['critical', 'low']);
  });

  it('combines filters', async () => {
    const scan = await seedFindings();
    const res = await getFindings(scan.id, { severity: 'critical,high', minConfidence: '0.5' });
    expect(res.body.map((f: Finding) => f.severity)).toEqual(['critical']);
  });

  it('rejects invalid filter values with 400', async () => {
    const scan = await seedFindings();
    expect((await getFindings(scan.id, { severity: 'catastrophic' })).status).toBe(400);
    expect((await getFindings(scan.id, { minConfidence: '2' })).status).toBe(400);
  });
});

describe('ownership', () => {
  it("returns 404 when user B accesses user A's project", async () => {
    const project = await createProject(alice);
    const url = `/api/projects/${project.id}`;

    expect((await request(app).get(url).set('Authorization', bob)).status).toBe(404);
    expect(
      (await request(app).patch(url).set('Authorization', bob).send({ name: 'pwned' })).status,
    ).toBe(404);
    expect((await request(app).delete(url).set('Authorization', bob)).status).toBe(404);
    expect((await request(app).post(`${url}/scans`).set('Authorization', bob)).status).toBe(404);
    expect((await request(app).get(`${url}/scans`).set('Authorization', bob)).status).toBe(404);

    // Unchanged and still present for the owner.
    const stillThere = await request(app).get(url).set('Authorization', alice);
    expect(stillThere.body.name).toBe(project.name);
    expect(await prisma.scan.count({ where: { projectId: project.id } })).toBe(0);
  });

  it("returns 404 when user B accesses user A's scan or findings", async () => {
    const project = await createProject(alice);
    const scan = await createScan(alice, project.id);

    expect((await request(app).get(`/api/scans/${scan.id}`).set('Authorization', bob)).status).toBe(
      404,
    );
    expect(
      (await request(app).get(`/api/scans/${scan.id}/findings`).set('Authorization', bob)).status,
    ).toBe(404);
  });
});

describe('GET /api/projects lastScan', () => {
  it('is null without scans and carries the newest scan with its rollup', async () => {
    const project = await createProject(alice);
    let res = await request(app).get('/api/projects').set('Authorization', alice);
    expect(res.body[0].lastScan).toBeNull();

    await createScan(alice, project.id);
    const newest = await createScan(alice, project.id);
    const rollup = { total: 2, grade: 'C', riskScore: 40 };
    await prisma.scan.update({
      where: { id: newest.id },
      data: { status: 'completed', finishedAt: new Date(), summaryJson: { rollup } },
    });

    res = await request(app).get('/api/projects').set('Authorization', alice);
    expect(res.body[0].lastScan).toMatchObject({
      id: newest.id,
      status: 'completed',
      finishedAt: expect.any(String),
      rollup,
    });
  });
});

describe('GET /api/scans/:id/file', () => {
  const savedMaxView = process.env.MAX_VIEW_FILE_KB;
  afterEach(() => {
    if (savedMaxView === undefined) delete process.env.MAX_VIEW_FILE_KB;
    else process.env.MAX_VIEW_FILE_KB = savedMaxView;
  });

  const CONFIG_JS = "const a = 1;\nconst key = 'sk_live_abcdef1234567890';\nmodule.exports = a;\n";

  /** A completed scan of alice's with an extracted copy in storage. */
  async function seedScan() {
    const project = await createProject(alice);
    const scan = await createScan(alice, project.id);
    const storage = getStorage();
    const base = storageKeys.extracted(scan.id);
    await storage.put(`${base}/src/config.js`, Buffer.from(CONFIG_JS));
    await storage.put(`${base}/server.js`, Buffer.from('const x = 1;\n'.repeat(400)));
    await storage.put(`${base}/bin/blob.dat`, Buffer.from([1, 0, 2]));
    await storage.put(`${base}/logo.png`, Buffer.from('not really a png'));
    await prisma.artifact.create({
      data: { scanId: scan.id, kind: 'extracted', storageKey: base },
    });
    await prisma.scan.update({
      where: { id: scan.id },
      data: {
        status: 'completed',
        finishedAt: new Date(),
        summaryJson: { skippedDirs: ['node_modules', 'web/dist'] },
      },
    });
    await prisma.finding.create({
      data: {
        scanId: scan.id,
        detectorId: 'A5-hardcoded-secrets',
        owaspCategory: 'A04:2025-Cryptographic Failures',
        severity: 'high',
        confidence: 0.9,
        filePath: 'src/config.js',
        lineStart: 2,
        lineEnd: 2,
        snippet: "const key = 'sk_l…[redacted]';",
        explanation: 'Hardcoded secret.',
        fixSuggestion: 'Use env vars.',
      },
    });
    return scan;
  }

  const get = (scanId: string, filePath: string | undefined, auth = alice) => {
    const req = request(app).get(`/api/scans/${scanId}/file`).set('Authorization', auth);
    return filePath === undefined ? req : req.query({ path: filePath });
  };

  it('returns the file with metadata, secret lines redacted', async () => {
    const scan = await seedScan();
    const res = await get(scan.id, 'src/config.js');
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('private, no-store');
    expect(res.body).toEqual({
      path: 'src/config.js',
      language: 'javascript',
      size: Buffer.byteLength(CONFIG_JS),
      lineCount: 3,
      content: "const a = 1;\nconst key = 'sk_l…[redacted]';\nmodule.exports = a;\n",
      truncated: false,
      binary: false,
      maxBytes: 2048 * 1024,
    });
    expect(JSON.stringify(res.body)).not.toContain('abcdef1234567890');
  });

  it('rejects traversal, absolute, and malformed paths with 400', async () => {
    const scan = await seedScan();
    const other = await seedScan();
    const bad = [
      undefined,
      '',
      '../x',
      'src/../../x',
      `../../${other.id}/extracted/src/config.js`,
      '../raw.zip',
      '/etc/passwd',
      'C:/Windows/win.ini',
      'C:\\Windows\\win.ini',
      'src\\config.js',
      'src//a',
      './a',
      'src/.',
      'a\u0000b',
      'a:b',
      'con',
      'x'.repeat(1025),
    ];
    for (const p of bad) {
      const res = await get(scan.id, p);
      expect(res.status, String(p)).toBe(400);
      expect(res.body.error, String(p)).toEqual(expect.any(String));
      expect(res.body).not.toHaveProperty('content');
    }
  });

  it('never follows a symlink out of the extracted directory', async () => {
    const scan = await seedScan();
    const extracted = path.join(config.storageDir, 'scans', scan.id, 'extracted');
    const outside = await mkdtemp(path.join(os.tmpdir(), 'webguard-outside-'));
    await writeFile(path.join(outside, 'secret.txt'), 'TOP SECRET');
    // A directory junction needs no privilege on Windows; a file symlink may (EPERM: skip it).
    await symlink(outside, path.join(extracted, 'linkdir'), 'junction');
    const paths = ['linkdir/secret.txt'];
    try {
      await symlink(path.join(outside, 'secret.txt'), path.join(extracted, 'link.txt'), 'file');
      paths.push('link.txt');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EPERM') throw err;
    }
    try {
      for (const p of paths) {
        const res = await get(scan.id, p);
        expect([400, 404], p).toContain(res.status);
        expect(JSON.stringify(res.body), p).not.toContain('TOP SECRET');
      }
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  it('truncates a file larger than MAX_VIEW_FILE_KB to whole lines', async () => {
    const scan = await seedScan();
    process.env.MAX_VIEW_FILE_KB = '1';
    const res = await get(scan.id, 'server.js');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ truncated: true, size: 13 * 400, maxBytes: 1024 });
    expect(res.body.content.length).toBeLessThanOrEqual(1024);
    expect(res.body.content.endsWith('const x = 1;\n')).toBe(true);
    expect(res.body.lineCount).toBe(Math.floor(1024 / 13));
  });

  it('flags binary files instead of returning bytes', async () => {
    const scan = await seedScan();
    for (const p of ['bin/blob.dat', 'logo.png']) {
      const res = await get(scan.id, p);
      expect(res.status, p).toBe(200);
      expect(res.body, p).toMatchObject({ binary: true, content: '', lineCount: 0 });
    }
  });

  it('explains why a file is missing', async () => {
    const scan = await seedScan();
    let res = await get(scan.id, 'node_modules/express/index.js');
    expect(res.status).toBe(404);
    expect(res.body).toMatchObject({ reason: 'ignored_dir', ignoredDir: 'node_modules' });
    expect(res.body.error).toMatch(/ignored dependency\/build directory/);

    // Recorded in the scan's own skippedDirs, even when not in the current ignore list.
    res = await get(scan.id, 'web/dist/app.js');
    expect(res.body).toMatchObject({ reason: 'ignored_dir', ignoredDir: 'web/dist' });

    res = await get(scan.id, 'nope.js');
    expect(res.status).toBe(404);
    expect(res.body).toMatchObject({ reason: 'not_found' });
    res = await get(scan.id, 'src');
    expect(res.status).toBe(404);
    expect(res.body).toMatchObject({ reason: 'not_found' });

    await getStorage().deletePrefix(storageKeys.extracted(scan.id));
    res = await get(scan.id, 'src/config.js');
    expect(res.status).toBe(404);
    expect(res.body).toMatchObject({ reason: 'extracted_unavailable' });
    expect(res.body.error).toMatch(/no longer available/);
  });

  it('reports a scan that has not been extracted yet', async () => {
    const project = await createProject(alice);
    const scan = await createScan(alice, project.id);
    const res = await get(scan.id, 'src/config.js');
    expect(res.status).toBe(404);
    expect(res.body).toMatchObject({ reason: 'not_ready' });
  });

  it("returns 404 for another user's scan, and 401 without a token", async () => {
    const scan = await seedScan();
    const res = await get(scan.id, 'src/config.js', bob);
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Not found' });
    expect((await request(app).get(`/api/scans/${scan.id}/file?path=server.js`)).status).toBe(401);
  });
});

describe('GET /api/scans/:id/compare', () => {
  async function completedScan(
    projectId: string,
    findings: {
      detectorId: string;
      snippet: string;
      lineStart: number;
      severity?: Finding['severity'];
    }[],
    riskScore: number,
  ) {
    const scan = await createScan(alice, projectId);
    await prisma.scan.update({
      where: { id: scan.id },
      data: {
        status: 'completed',
        finishedAt: new Date(),
        summaryJson: { rollup: { total: findings.length, riskScore, grade: 'C' } },
      },
    });
    for (const x of findings) {
      await prisma.finding.create({
        data: {
          scanId: scan.id,
          detectorId: x.detectorId,
          owaspCategory: 'A05:2025-Injection',
          severity: x.severity ?? 'high',
          confidence: 0.9,
          filePath: 'src/app.js',
          lineStart: x.lineStart,
          lineEnd: x.lineStart,
          snippet: x.snippet,
          explanation: 'e',
          fixSuggestion: 'f',
        },
      });
    }
    return scan;
  }

  const compare = (id: string, against: string, auth = alice) =>
    request(app).get(`/api/scans/${id}/compare`).query({ against }).set('Authorization', auth);

  it('returns fixed, new, and persisting findings with deltas', async () => {
    const project = await createProject(alice);
    const before = await completedScan(
      project.id,
      [
        { detectorId: 'A1-sql-injection', snippet: 'db.query(q + id)', lineStart: 3 },
        { detectorId: 'A4-xss', snippet: 'el.innerHTML = q', lineStart: 9 },
      ],
      60,
    );
    const after = await completedScan(
      project.id,
      [
        { detectorId: 'A1-sql-injection', snippet: 'db.query(q  +  id)', lineStart: 7 },
        {
          detectorId: 'A6-weak-crypto',
          snippet: "createHash('md5')",
          lineStart: 2,
          severity: 'medium',
        },
      ],
      45,
    );

    const res = await compare(after.id, before.id);
    expect(res.status).toBe(200);
    expect(res.body.scan.id).toBe(after.id);
    expect(res.body.against.id).toBe(before.id);
    expect(res.body.fixed.map((x: Finding) => x.detectorId)).toEqual(['A4-xss']);
    expect(res.body.new.map((x: Finding) => x.detectorId)).toEqual(['A6-weak-crypto']);
    expect(res.body.persisting).toHaveLength(1);
    expect(res.body.persisting[0].finding.lineStart).toBe(7);
    expect(res.body.persisting[0].previous.lineStart).toBe(3);
    expect(res.body.summary).toEqual({
      fixed: 1,
      new: 1,
      persisting: 1,
      totalDelta: 0,
      riskScoreDelta: -15,
    });
  });

  it('rejects scans from different projects, incomplete scans, and bad ids', async () => {
    const p1 = await createProject(alice, 'one');
    const p2 = await createProject(alice, 'two');
    const a = await completedScan(p1.id, [], 0);
    const b = await completedScan(p2.id, [], 0);
    const queued = await createScan(alice, p1.id);

    expect((await compare(a.id, b.id)).status).toBe(400);
    expect((await compare(a.id, queued.id)).status).toBe(409);
    expect((await compare(a.id, 'nope')).status).toBe(400);
    expect(
      (await request(app).get(`/api/scans/${a.id}/compare`).set('Authorization', alice)).status,
    ).toBe(400);
  });

  it("returns 404 for another user's scans", async () => {
    const project = await createProject(alice);
    const a = await completedScan(project.id, [], 0);
    const b = await completedScan(project.id, [], 0);
    expect((await compare(a.id, b.id, bob)).status).toBe(404);
  });
});
