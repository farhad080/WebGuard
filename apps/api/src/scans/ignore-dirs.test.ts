import { existsSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DEFAULT_IGNORED_DIRS } from '@webguard/analysis';
import type { Scan } from '@webguard/core';
import request from 'supertest';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createUserWithToken, resetDatabase } from '../../test/helpers.js';
import { buildZip, type ZipEntrySpec } from '../../test/zip-writer.js';
import { createApp } from '../app.js';
import { config } from '../config.js';
import { prisma } from '../db.js';
import { ExtractorService, type ExtractionLimits } from './extractor.js';
import { processScan } from './process-scan.js';
import { closeScanQueue, getScanQueue } from './queue.js';
import { getStorage } from './storage.js';

/**
 * Dependency/build/VCS directories are skipped during extraction, before the file-count, size,
 * and ratio caps. Caps are lowered via env so small archives stand in for a real project with
 * ~90k files in node_modules.
 */

const VARS = [
  'EXTRACT_IGNORE_DIRS',
  'MAX_EXTRACTED_FILES',
  'MAX_EXTRACTED_MB',
  'MAX_COMPRESSION_RATIO',
] as const;

async function withEnv<T>(vars: Partial<Record<string, string>>, fn: () => Promise<T>): Promise<T> {
  const saved = new Map(VARS.map((k) => [k, process.env[k]]));
  for (const k of VARS) delete process.env[k];
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

/** A small Express app with a vulnerable root dependency and a huge installed node_modules. */
function projectWithNodeModules(depFiles: number): ZipEntrySpec[] {
  const entries: ZipEntrySpec[] = [
    {
      name: 'package.json',
      data: JSON.stringify({ name: 'shop', dependencies: { express: '4.18.2', lodash: '4.17.4' } }),
    },
    {
      name: 'package-lock.json',
      data: JSON.stringify({
        name: 'shop',
        lockfileVersion: 3,
        packages: {
          '': { name: 'shop', dependencies: { lodash: '4.17.4' } },
          'node_modules/lodash': { version: '4.17.4' },
        },
      }),
    },
    { name: 'src/app.js', data: "const express = require('express');\nmodule.exports = 1;\n" },
    { name: 'node_modules/' },
    { name: 'node_modules/lodash/' },
    { name: 'node_modules/lodash/package.json', data: '{"name":"lodash","version":"4.17.4"}' },
  ];
  for (let i = 0; i < depFiles; i++) {
    entries.push({
      name: `node_modules/pkg${i % 50}/lib/file${i}.js`,
      data: `module.exports=${i};`,
    });
  }
  return entries;
}

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
    .send({ name: 'Shop' });
  projectId = res.body.id;
});

afterAll(async () => {
  await getScanQueue().obliterate({ force: true });
  await closeScanQueue();
  await prisma.$disconnect();
});

async function queued(entries: ZipEntrySpec[]): Promise<string> {
  const res = await request(app)
    .post(`/api/projects/${projectId}/scans`)
    .set('Authorization', alice)
    .attach('file', buildZip(entries), { filename: 'shop.zip', contentType: 'application/zip' });
  expect(res.status).toBe(201);
  return res.body.id as string;
}

async function getScan(scanId: string): Promise<Scan> {
  const res = await request(app).get(`/api/scans/${scanId}`).set('Authorization', alice);
  return res.body as Scan;
}

describe('scan of a project with a huge node_modules (caps lowered via env)', () => {
  it('extracts and scans: node_modules is skipped, not counted, and reported', async () => {
    // 3,000 dependency files against a file-count cap of 20: only the 3 project files count.
    const scanId = await queued(projectWithNodeModules(3000));
    await withEnv({ MAX_EXTRACTED_FILES: '20' }, () => processScan(scanId));

    const scan = await getScan(scanId);
    expect(scan.status).toBe('completed');
    expect(scan.summary).toMatchObject({
      extractedFiles: 3,
      filesExtracted: 3,
      skippedDirs: ['node_modules'],
      skippedFileCount: 3001, // + node_modules/lodash/package.json
      skippedEntries: 0,
    });

    // The root manifests were extracted and profiled…
    expect(scan.summary!.profile!.manifests.map((m) => m.path).sort()).toEqual([
      'package-lock.json',
      'package.json',
    ]);
    // …and the dependency detector still ran on them.
    expect(scan.summary!.detectors).toContain('A11-vulnerable-deps');
    const findings = await prisma.finding.findMany({
      where: { scanId, detectorId: 'A11-vulnerable-deps' },
    });
    expect(findings.some((f) => f.evidence.some((e) => /lodash/.test(e)))).toBe(true);
    expect(findings.every((f) => !f.filePath.includes('node_modules'))).toBe(true);

    // Reports carry it too ("ignored N dependency/build files").
    const report = await request(app)
      .get(`/api/scans/${scanId}/report.json`)
      .set('Authorization', alice);
    expect(report.body.profile).toMatchObject({
      skippedFileCount: 3001,
      skippedDirs: ['node_modules'],
    });
    const html = await request(app)
      .get(`/api/scans/${scanId}/report.html`)
      .set('Authorization', alice);
    expect(html.text).toContain('ignored 3001 dependency/build files (node_modules)');
  });

  it('still fails on the file-count cap when the project itself has too many files', async () => {
    const entries = projectWithNodeModules(100);
    for (let i = 0; i < 30; i++) entries.push({ name: `src/gen/f${i}.js`, data: '1' });
    const scanId = await queued(entries);
    await withEnv({ MAX_EXTRACTED_FILES: '20' }, () =>
      expect(processScan(scanId)).rejects.toThrow(),
    );
    const scan = await getScan(scanId);
    expect(scan.status).toBe('failed');
    expect(scan.summary?.error).toMatch(/too many entries .*limit 20, MAX_EXTRACTED_FILES/);
  });

  it('honors EXTRACT_IGNORE_DIRS (replaces the default list)', async () => {
    const scanId = await queued([
      { name: 'src/app.js', data: '1' },
      { name: 'generated/a.js', data: '1' },
      { name: 'node_modules/x/index.js', data: '1' },
    ]);
    await withEnv({ EXTRACT_IGNORE_DIRS: 'generated' }, () => processScan(scanId));
    const scan = await getScan(scanId);
    expect(scan.summary).toMatchObject({
      extractedFiles: 2, // node_modules is no longer ignored
      skippedDirs: ['generated'],
      skippedFileCount: 1,
    });
  });
});

describe('config.ignoredDirs (EXTRACT_IGNORE_DIRS)', () => {
  it('defaults to the shared list used by the profiler', async () => {
    await withEnv({}, async () => {
      expect(config.ignoredDirs).toBe(DEFAULT_IGNORED_DIRS);
      expect(config.extraction.ignoredDirs).toBe(DEFAULT_IGNORED_DIRS);
      for (const dir of [
        'node_modules',
        '.git',
        'dist',
        'build',
        'out',
        '.next',
        '.nuxt',
        'coverage',
        'vendor',
        'bower_components',
        '.gradle',
        'target',
        '__pycache__',
        '.venv',
        'venv',
      ]) {
        expect(config.ignoredDirs).toContain(dir);
      }
      expect(config.extraction.maxFiles).toBe(100_000);
    });
  });

  it('parses a comma-separated override, and "none" disables skipping', async () => {
    await withEnv({ EXTRACT_IGNORE_DIRS: ' node_modules , .git,, tmp ' }, async () => {
      expect(config.ignoredDirs).toEqual(['node_modules', '.git', 'tmp']);
    });
    await withEnv({ EXTRACT_IGNORE_DIRS: 'none' }, async () => {
      expect(config.ignoredDirs).toEqual([]);
    });
  });

  it('rejects entries that are paths rather than directory names', async () => {
    await withEnv({ EXTRACT_IGNORE_DIRS: 'node_modules,a/b' }, async () => {
      expect(() => config.ignoredDirs).toThrow(/EXTRACT_IGNORE_DIRS/);
    });
  });
});

describe('ExtractorService with ignored dirs', () => {
  const limits: ExtractionLimits = {
    maxTotalBytes: 10_000,
    maxFiles: 5,
    maxCompressionRatio: 100,
    ratioCheckMinBytes: 1024 * 1024,
    ignoredDirs: DEFAULT_IGNORED_DIRS,
  };
  let workDir: string;
  let dest: string;

  beforeEach(async () => {
    workDir = await mkdtemp(path.join(os.tmpdir(), 'webguard-ignore-test-'));
    dest = path.join(workDir, 'a', 'b', 'out');
  });
  afterEach(async () => {
    await rm(workDir, { recursive: true, force: true });
  });

  async function extract(entries: ZipEntrySpec[], overrides: Partial<ExtractionLimits> = {}) {
    const file = path.join(workDir, 'archive.zip');
    await writeFile(file, buildZip(entries));
    return new ExtractorService({ ...limits, ...overrides }).extract(file, dest);
  }

  it('skips ignored segments anywhere in the path, and never writes them', async () => {
    const result = await extract([
      { name: 'package.json', data: '{}' },
      { name: 'packages/web/node_modules/react/index.js', data: 'x' },
      { name: 'packages/web/dist/bundle.js', data: 'x' },
      { name: 'packages/web/src/index.js', data: 'x' },
      { name: '.git/HEAD', data: 'ref: refs/heads/main' },
      { name: 'api/__pycache__/m.pyc', data: 'x' },
      { name: 'api/.venv/lib/site.py', data: 'x' },
      { name: 'build', data: 'a FILE named build is not a directory: kept' },
    ]);
    expect(result).toMatchObject({
      filesExtracted: 3,
      skippedFileCount: 5,
      skippedDirs: [
        '.git',
        'api/.venv',
        'api/__pycache__',
        'packages/web/dist',
        'packages/web/node_modules',
      ],
    });
    expect(existsSync(path.join(dest, 'package.json'))).toBe(true);
    expect(existsSync(path.join(dest, 'build'))).toBe(true);
    expect(existsSync(path.join(dest, 'packages/web/node_modules'))).toBe(false);
    expect(existsSync(path.join(dest, '.git'))).toBe(false);
  });

  it('does not count ignored entries toward the size cap or the ratio check', async () => {
    const result = await extract([
      { name: 'index.js', data: 'x' },
      // 50 KB (cap is 10 KB) and a ~1000:1 bomb, both inside node_modules: never read.
      { name: 'node_modules/big/blob.js', data: 'y'.repeat(50_000) },
      { name: 'node_modules/bomb/zeros.bin', data: Buffer.alloc(8 * 1024 * 1024), deflate: true },
    ]);
    expect(result).toMatchObject({ filesExtracted: 1, skippedFileCount: 2 });
    expect(result.totalBytes).toBe(1);
  });

  it('still applies zip-bomb caps to entries that are extracted', async () => {
    await expect(
      extract([{ name: 'src/zeros.bin', data: Buffer.alloc(8 * 1024 * 1024), deflate: true }], {
        maxTotalBytes: 100 * 1024 * 1024,
      }),
    ).rejects.toThrow(/compression ratio/);
    await expect(extract([{ name: 'src/big.js', data: 'y'.repeat(50_000) }])).rejects.toThrow(
      /maximum uncompressed size/,
    );
  });

  it('still rejects zip-slip, even when the path also names an ignored dir', async () => {
    await expect(extract([{ name: '../../evil.js', data: 'x' }])).rejects.toThrow(/unsafe path/i);
    await expect(extract([{ name: 'node_modules/../../../evil.js', data: 'x' }])).rejects.toThrow(
      /unsafe path/i,
    );
    expect(existsSync(path.join(workDir, 'evil.js'))).toBe(false);
  });

  it('extracts everything when the ignore list is empty', async () => {
    const result = await extract(
      [
        { name: 'index.js', data: 'x' },
        { name: 'node_modules/a/index.js', data: 'x' },
      ],
      { ignoredDirs: [] },
    );
    expect(result).toMatchObject({ filesExtracted: 2, skippedFileCount: 0, skippedDirs: [] });
  });
});
