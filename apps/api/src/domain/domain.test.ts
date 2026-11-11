import { fileURLToPath } from 'node:url';
import type { Finding, Project, Scan } from '@webguard/core';
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { createUserWithToken, resetDatabase } from '../../test/helpers.js';
import { createApp } from '../app.js';
import { prisma } from '../db.js';
import { closeScanQueue, getScanQueue } from '../scans/queue.js';

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
