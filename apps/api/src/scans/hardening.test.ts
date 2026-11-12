import { existsSync } from 'node:fs';
import { readdir, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDefaultDetectorRegistry, DetectorRegistry, type Detector } from '@webguard/analysis';
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createUserWithToken, resetDatabase } from '../../test/helpers.js';
import { buildZip } from '../../test/zip-writer.js';
import { createApp } from '../app.js';
import { config } from '../config.js';
import { prisma } from '../db.js';
import { installNetworkGuard, ScanLimitError } from './analyze.js';
import { processScan } from './process-scan.js';
import { closeScanQueue, getScanQueue } from './queue.js';
import { runAnalysisInThread } from './sandbox.js';
import { getStorage, storageKeys } from './storage.js';

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
    .send({ name: 'S' });
  projectId = res.body.id;
});

afterAll(async () => {
  await getScanQueue().obliterate({ force: true });
  await closeScanQueue();
  await prisma.$disconnect();
});

async function queuedScan(zip: Buffer): Promise<string> {
  const res = await request(app)
    .post(`/api/projects/${projectId}/scans`)
    .set('Authorization', alice)
    .attach('file', zip, { filename: 'site.zip', contentType: 'application/zip' });
  expect(res.status).toBe(201);
  return res.body.id;
}

async function tempDirsFor(scanId: string): Promise<string[]> {
  return (await readdir(os.tmpdir())).filter((d) => d.startsWith(`webguard-scan-${scanId}-`));
}

describe('uploaded code is never executed', () => {
  it('scans a project whose every entry point would write a marker if run — none is written', async () => {
    const marker = path.join(os.tmpdir(), `webguard-exec-marker-${Date.now()}`);
    const payload = `require('fs').writeFileSync(${JSON.stringify(marker)}, 'executed');`;
    const scanId = await queuedScan(
      buildZip([
        {
          name: 'package.json',
          data: JSON.stringify({
            name: 'hostile',
            main: 'index.js',
            scripts: { preinstall: payload, postinstall: payload, prepare: payload },
          }),
        },
        { name: 'index.js', data: `${payload}\nmodule.exports = {};` },
        { name: 'webpack.config.js', data: payload },
        { name: 'babel.config.js', data: payload },
        {
          name: 'src/esm.mjs',
          data: `import fs from 'fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'x');`,
        },
        { name: 'src/eval.js', data: `eval(${JSON.stringify(payload)});` },
        { name: 'node_modules/evil/index.js', data: payload },
      ]),
    );

    await processScan(scanId);

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    expect(scan.status).toBe('completed');
    expect(existsSync(marker)).toBe(false);
    await rm(marker, { force: true });
  });

  it('the analysis code has no way to load or run project code', async () => {
    // Static guard over the analysis package + the API's scan pipeline: no dynamic module
    // loading, no VM/child-process/eval of scanned content.
    const roots = [
      fileURLToPath(new URL('../../../../packages/analysis/src', import.meta.url)),
      fileURLToPath(new URL('.', import.meta.url)),
    ];
    const forbidden: [RegExp, string][] = [
      [/from ['"](node:)?(vm|child_process|module)['"]/, 'imports vm/child_process/module'],
      [/\bcreateRequire\b/, 'createRequire'],
      [/\brequire\.resolve\b|\brequire\(\s*[^'"\s)]/, 'require() of a computed path'],
      [/\bimport\(\s*[^'"\s)]/, 'import() of a computed path'],
      [/(^|[^.\w'"`])eval\(/, 'eval()'],
      [/\bnew Function\(/, 'new Function()'],
    ];
    const offenders: string[] = [];
    const walk = async (dir: string) => {
      for (const e of await readdir(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) await walk(p);
        else if (/\.ts$/.test(e.name) && !/\.test\.ts$/.test(e.name)) {
          const lines = (await readFile(p, 'utf8')).split('\n');
          lines.forEach((line, i) => {
            const code = line.replace(/(['"`])(?:\\.|(?!\1).)*\1/g, '""'); // strip string literals
            if (/^\s*(\/\/|\*)/.test(code)) return;
            for (const [re, what] of forbidden) {
              if (re.test(code)) offenders.push(`${path.relative(roots[0]!, p)}:${i + 1} ${what}`);
            }
          });
        }
      }
    };
    for (const r of roots) await walk(r);
    expect(offenders).toEqual([]);
  });
});

describe('analysis isolation limits', () => {
  const hostile = (name: string) => new URL(`../../test/hostile/${name}`, import.meta.url);
  const input = {
    extractDir: os.tmpdir(),
    maxFileBytes: 1024,
    network: { osv: false },
    llm: { enabled: false },
  };

  it('terminates a thread that never yields when the time limit is reached', async () => {
    const started = Date.now();
    await expect(
      runAnalysisInThread(input, { timeoutMs: 1500, maxHeapMb: 256, entry: hostile('spin.ts') }),
    ).rejects.toThrow(ScanLimitError);
    expect(Date.now() - started).toBeLessThan(10_000);
  });

  it('stops a thread that exhausts its heap with a memory-limit error', async () => {
    await expect(
      runAnalysisInThread(input, { timeoutMs: 20_000, maxHeapMb: 64, entry: hostile('alloc.ts') }),
    ).rejects.toThrow(/memory limit/);
  });

  it('fails a runaway scan cleanly: status, reason, and no leftover files', async () => {
    const slow: Detector = {
      id: 'slow-detector',
      title: 'slow',
      owaspCategory: 'A05:2025-Injection',
      technique: 'pattern',
      explanation: 'x',
      fixSuggestion: 'x',
      run: () => new Promise((resolve) => setTimeout(() => resolve([]), 5_000)),
    };
    const registry = new DetectorRegistry([slow, ...createDefaultDetectorRegistry().list()]);
    const scanId = await queuedScan(buildZip([{ name: 'index.js', data: 'console.log(1);' }]));

    await expect(processScan(scanId, { detectors: registry, timeoutMs: 800 })).rejects.toThrow(
      ScanLimitError,
    );

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    expect(scan.status).toBe('failed');
    expect(scan.summaryJson).toEqual({ error: expect.stringMatching(/time limit/) });
    const storage = getStorage();
    expect(await storage.list(storageKeys.scanRoot(scanId))).toEqual([]);
    expect(await prisma.artifact.count({ where: { scanId } })).toBe(0);
    expect(await tempDirsFor(scanId)).toEqual([]);
  });

  it('a completed scan keeps only the extracted tree (no upload, no temp dir)', async () => {
    const scanId = await queuedScan(buildZip([{ name: 'index.js', data: 'console.log(1);' }]));
    await processScan(scanId);
    const storage = getStorage();
    expect(await storage.exists(storageKeys.rawZip(scanId))).toBe(false);
    expect(await storage.list(storageKeys.extracted(scanId))).toHaveLength(1);
    const kinds = (await prisma.artifact.findMany({ where: { scanId } })).map((a) => a.kind);
    expect(kinds).toEqual(['extracted']);
    expect(await tempDirsFor(scanId)).toEqual([]);
  });

  it('deleting a project removes its stored files', async () => {
    const scanId = await queuedScan(buildZip([{ name: 'index.js', data: 'console.log(1);' }]));
    await processScan(scanId);
    expect(await getStorage().list(storageKeys.scanRoot(scanId))).not.toEqual([]);
    const res = await request(app).delete(`/api/projects/${projectId}`).set('Authorization', alice);
    expect(res.status).toBe(204);
    expect(await getStorage().list(storageKeys.scanRoot(scanId))).toEqual([]);
  });
});

describe('network policy', () => {
  it('is offline by default, and OFFLINE=true overrides the opt-in flags', () => {
    vi.stubEnv('OFFLINE', '');
    vi.stubEnv('OSV_ADVISORIES', '');
    vi.stubEnv('REMEDIATION_LLM', '');
    expect(config.osvAdvisories).toBe(false);
    expect(config.remediationLlm.enabled).toBe(false);

    vi.stubEnv('OSV_ADVISORIES', 'true');
    vi.stubEnv('REMEDIATION_LLM', 'true');
    vi.stubEnv('ANTHROPIC_API_KEY', 'sk-test');
    expect(config.osvAdvisories).toBe(true);
    expect(config.remediationLlm.enabled).toBe(true);

    vi.stubEnv('OFFLINE', 'true');
    expect(config.osvAdvisories).toBe(false);
    expect(config.remediationLlm.enabled).toBe(false);
    vi.unstubAllEnvs();
  });

  it('the analysis network guard only lets opted-in hosts through', async () => {
    const original = globalThis.fetch;
    const inner = vi.fn(async () => new Response('{}'));
    globalThis.fetch = inner as unknown as typeof fetch;
    try {
      installNetworkGuard(['api.osv.dev']);
      await expect(fetch('https://attacker.example/x')).rejects.toThrow(/disabled for scans/);
      await expect(fetch('http://169.254.169.254/latest/meta-data')).rejects.toThrow();
      await fetch('https://api.osv.dev/v1/querybatch', { method: 'POST' });
      expect(inner).toHaveBeenCalledTimes(1);

      installNetworkGuard([]);
      await expect(fetch('https://api.osv.dev/v1/querybatch')).rejects.toThrow();
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe('HTTP surface', () => {
  it('rate-limits credential endpoints per client', async () => {
    const limited = createApp({ rateLimits: { auth: 3 } });
    const attempt = () =>
      request(limited).post('/api/auth/login').send({ email: 'x@example.com', password: 'nope' });
    for (let i = 0; i < 3; i++) expect((await attempt()).status).toBe(401);
    const blocked = await attempt();
    expect(blocked.status).toBe(429);
    expect(blocked.body.error).toMatch(/too many/i);
    expect(blocked.headers['ratelimit-policy']).toBeDefined();
    // Session checks are not credential attempts and stay available.
    expect((await request(limited).get('/api/auth/me')).status).toBe(401);
  });

  it('rate-limits uploads per user', async () => {
    const limited = createApp({ rateLimits: { upload: 1 } });
    const zip = buildZip([{ name: 'a.js', data: '1' }]);
    const up = () =>
      request(limited)
        .post(`/api/projects/${projectId}/scans`)
        .set('Authorization', alice)
        .attach('file', zip, { filename: 'a.zip', contentType: 'application/zip' });
    expect((await up()).status).toBe(201);
    expect((await up()).status).toBe(429);
    // Unauthenticated uploads are rejected before they count against anyone.
    expect((await request(limited).post(`/api/projects/${projectId}/scans`)).status).toBe(401);
  });

  it('allows CORS only from the configured frontend origin', async () => {
    const strict = createApp({ corsOrigins: ['https://app.webguard.test'] });
    const preflight = (origin: string) =>
      request(strict)
        .options('/api/projects')
        .set('Origin', origin)
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'authorization,content-type');
    const ok = await preflight('https://app.webguard.test');
    expect(ok.headers['access-control-allow-origin']).toBe('https://app.webguard.test');
    const evil = await preflight('https://evil.example');
    expect(evil.headers['access-control-allow-origin']).toBeUndefined();
    const plain = await request(strict).get('/api/health').set('Origin', 'https://evil.example');
    expect(plain.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('never serves stored files statically', async () => {
    const scanId = await queuedScan(buildZip([{ name: 'index.js', data: 'secret' }]));
    for (const p of [
      `/storage/scans/${scanId}/raw.zip`,
      `/scans/${scanId}/raw.zip`,
      `/api/scans/${scanId}/raw.zip`,
      `/api/../storage/scans/${scanId}/raw.zip`,
    ]) {
      const res = await request(app).get(p).set('Authorization', alice);
      expect(res.status, p).toBe(404);
    }
  });
});
