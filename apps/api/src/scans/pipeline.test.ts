import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Scan } from '@webguard/core';
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
    expect(final.summary).toEqual({
      filesExtracted: 3,
      totalBytes: expect.any(Number),
      skippedEntries: 0,
      detectors: [],
    });

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
