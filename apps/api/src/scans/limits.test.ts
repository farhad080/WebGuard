import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { deflateRawSync } from 'node:zlib';
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { createUserWithToken, resetDatabase } from '../../test/helpers.js';
import { buildZip } from '../../test/zip-writer.js';
import { configureServerTimeouts, createApp } from '../app.js';
import { config } from '../config.js';
import { prisma } from '../db.js';
import { processScan } from './process-scan.js';
import { closeScanQueue, getScanQueue } from './queue.js';
import { getStorage } from './storage.js';

/**
 * Upload / extraction limits are read from the environment on every request or job, so these
 * tests lower them via env (small fixtures standing in for 300 MB archives) instead of
 * shipping real large files.
 */

const LIMIT_VARS = [
  'MAX_UPLOAD_MB',
  'MAX_UPLOAD_BYTES',
  'MAX_EXTRACTED_MB',
  'MAX_EXTRACTED_FILES',
  'MAX_COMPRESSION_RATIO',
  'EXTRACT_MAX_TOTAL_BYTES',
  'EXTRACT_MAX_FILES',
  'EXTRACT_MAX_COMPRESSION_RATIO',
  'UPLOAD_TIMEOUT_MS',
] as const;

async function withEnv<T>(vars: Partial<Record<string, string>>, fn: () => Promise<T>): Promise<T> {
  const saved = new Map(LIMIT_VARS.map((k) => [k, process.env[k]]));
  for (const k of LIMIT_VARS) delete process.env[k];
  Object.assign(process.env, vars);
  try {
    return await fn();
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const KiB = 1024;
const app = createApp();
let alice: string;
let projectId: string;

beforeEach(async () => {
  await resetDatabase();
  await getScanQueue().obliterate({ force: true });
  await getStorage().deletePrefix('scans');
  alice = (await createUserWithToken('alice@example.com')).auth;
  const res = await request(app)
    .post('/api/projects')
    .set('Authorization', alice)
    .send({ name: 'Big project' });
  projectId = res.body.id;
});

afterAll(async () => {
  await getScanQueue().obliterate({ force: true });
  await closeScanQueue();
  await prisma.$disconnect();
});

function uploadZip(zip: Buffer) {
  return request(app)
    .post(`/api/projects/${projectId}/scans`)
    .set('Authorization', alice)
    .attach('file', zip, { filename: 'big.zip', contentType: 'application/zip' });
}

/** A stored (uncompressed) ZIP of roughly `bytes` incompressible bytes. */
function zipOfSize(bytes: number): Buffer {
  return buildZip([
    { name: 'src/app.js', data: 'module.exports = 1;\n' },
    { name: 'assets/blob.bin', data: randomBytes(bytes) },
  ]);
}

describe('limit configuration (env-driven)', () => {
  it('uses the raised defaults when nothing is set', async () => {
    await withEnv({}, async () => {
      expect(config.maxUploadMb).toBe(512);
      expect(config.maxUploadBytes).toBe(512 * 1024 * 1024);
      expect(config.uploadTimeoutMs).toBe(600_000);
      expect(config.extraction).toMatchObject({
        maxTotalBytes: 2048 * 1024 * 1024,
        maxFiles: 100_000,
        maxCompressionRatio: 200,
      });
    });
  });

  it('reads every limit from its env var', async () => {
    await withEnv(
      {
        MAX_UPLOAD_MB: '1024',
        MAX_EXTRACTED_MB: '4096',
        MAX_EXTRACTED_FILES: '100000',
        MAX_COMPRESSION_RATIO: '50',
        UPLOAD_TIMEOUT_MS: '900000',
      },
      async () => {
        expect(config.maxUploadBytes).toBe(1024 * 1024 * 1024);
        expect(config.uploadTimeoutMs).toBe(900_000);
        expect(config.extraction).toMatchObject({
          maxTotalBytes: 4096 * 1024 * 1024,
          maxFiles: 100_000,
          maxCompressionRatio: 50,
        });
      },
    );
  });

  it('still honors the older byte-based names when the new ones are unset', async () => {
    await withEnv(
      {
        MAX_UPLOAD_BYTES: String(10 * 1024 * 1024),
        EXTRACT_MAX_TOTAL_BYTES: String(20 * 1024 * 1024),
        EXTRACT_MAX_FILES: '123',
        EXTRACT_MAX_COMPRESSION_RATIO: '42',
      },
      async () => {
        expect(config.maxUploadMb).toBe(10);
        expect(config.extraction).toMatchObject({
          maxTotalBytes: 20 * 1024 * 1024,
          maxFiles: 123,
          maxCompressionRatio: 42,
        });
      },
    );
  });

  it('rejects a non-numeric limit instead of silently disabling it', async () => {
    await withEnv({ MAX_UPLOAD_MB: 'lots' }, async () => {
      expect(() => config.maxUploadBytes).toThrow(/MAX_UPLOAD_MB/);
    });
  });

  it('exposes the upload cap to the SPA at GET /api/limits', async () => {
    await withEnv({ MAX_UPLOAD_MB: '300' }, async () => {
      const res = await request(app).get('/api/limits');
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ maxUploadMb: 300, maxUploadBytes: 300 * 1024 * 1024 });
    });
  });

  it('raises the HTTP server request timeout to UPLOAD_TIMEOUT_MS', async () => {
    await withEnv({ UPLOAD_TIMEOUT_MS: '720000' }, async () => {
      const server = configureServerTimeouts(createServer());
      expect(server.requestTimeout).toBe(720_000);
    });
  });
});

// Scale model: 1 "MB" of the real limits = 1 KiB here. The old cap was 50, the new default
// is 512, and the user's archive is ~300 — so a 300 KiB upload must pass a 512 KiB cap.
describe('upload size limit (MAX_UPLOAD_MB)', () => {
  const file = zipOfSize(300 * KiB);

  it('accepts a file between the old (50) and new (512) limit, past the 100 kB JSON cap', async () => {
    await withEnv({ MAX_UPLOAD_MB: String(512 / 1024) }, async () => {
      const res = await uploadZip(file);
      expect(res.status).toBe(201);
      expect(res.body.status).toBe('queued');
    });
  });

  it('rejects a file over MAX_UPLOAD_MB with 413 stating the limit', async () => {
    await withEnv({ MAX_UPLOAD_MB: '0.25' }, async () => {
      const res = await uploadZip(file);
      expect(res.status).toBe(413);
      expect(res.body).toEqual({
        error: 'File exceeds the 0.25 MB upload limit (MAX_UPLOAD_MB)',
        limitMb: 0.25,
        limitBytes: 256 * KiB,
      });
    });
    expect(await prisma.scan.count()).toBe(0);
  });
});

describe('extraction caps from env (zip-bomb guard)', () => {
  async function queued(zip: Buffer): Promise<string> {
    const res = await uploadZip(zip);
    expect(res.status).toBe(201);
    return res.body.id as string;
  }

  async function failureReason(scanId: string): Promise<string> {
    await expect(processScan(scanId)).rejects.toThrow();
    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    expect(scan.status).toBe('failed');
    return (scan.summaryJson as { error: string }).error;
  }

  it('fails safely, with the reason, when the archive is too big once extracted', async () => {
    const scanId = await queued(zipOfSize(200 * KiB));
    // 100 KiB cap: the upload itself was fine, the extracted size is not.
    const reason = await withEnv({ MAX_EXTRACTED_MB: String(100 / 1024) }, () =>
      failureReason(scanId),
    );
    expect(reason).toMatch(/maximum uncompressed size/i);
    expect(reason).toContain('MAX_EXTRACTED_MB');
    // Nothing of the archive is left behind.
    expect(await prisma.artifact.count({ where: { scanId, kind: 'extracted' } })).toBe(0);
  });

  it('fails with the reason when MAX_EXTRACTED_FILES is exceeded', async () => {
    const scanId = await queued(
      buildZip(Array.from({ length: 12 }, (_, i) => ({ name: `f${i}.js`, data: '1' }))),
    );
    const reason = await withEnv({ MAX_EXTRACTED_FILES: '10' }, () => failureReason(scanId));
    expect(reason).toMatch(
      /too many entries \(more than 10 outside ignored directories; limit 10, MAX_EXTRACTED_FILES\)/,
    );
  });

  it('still stops a zip bomb at the raised default ratio (200:1)', async () => {
    // 8 MiB of zeros deflates ~1000:1.
    const scanId = await queued(
      buildZip([{ name: 'bomb.bin', data: Buffer.alloc(8 * 1024 * 1024), deflate: true }]),
    );
    const reason = await withEnv({}, () => failureReason(scanId));
    expect(reason).toMatch(/compression ratio \(200:1; MAX_COMPRESSION_RATIO\)/);
  });

  it('still blocks zip-slip with the raised caps', async () => {
    const scanId = await queued(buildZip([{ name: '../../escape.js', data: 'x' }]));
    const reason = await withEnv({}, () => failureReason(scanId));
    expect(reason).toMatch(/unsafe path in archive/i);
  });

  it('scans an archive that the old caps would have rejected but the new defaults allow', async () => {
    // 150:1 (old cap 100, new 200): 1.5 MiB with 10 KiB of random bytes, rest zeros.
    const data = Buffer.concat([randomBytes(10 * KiB), Buffer.alloc(1536 * KiB - 10 * KiB)]);
    const ratio = data.length / deflateRawSync(data).length;
    expect(ratio).toBeGreaterThan(100);
    expect(ratio).toBeLessThan(200);
    const zip = buildZip([
      { name: 'src/app.js', data: 'module.exports = 1;\n' },
      { name: 'assets/data.bin', data, deflate: true },
    ]);
    const scanId = await queued(zip);
    await withEnv({}, () => processScan(scanId));
    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    expect(scan.status).toBe('completed');
  });
});
