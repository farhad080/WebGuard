import { existsSync } from 'node:fs';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildZip, type ZipEntrySpec } from '../../test/zip-writer.js';
import {
  ExtractionError,
  ExtractorService,
  resolveSafeEntryPath,
  type ExtractionLimits,
} from './extractor.js';

const fixture = (name: string) =>
  fileURLToPath(new URL(`../../test/fixtures/${name}`, import.meta.url));

const defaults: ExtractionLimits = {
  maxTotalBytes: 500 * 1024 * 1024,
  maxFiles: 20_000,
  maxCompressionRatio: 100,
  ratioCheckMinBytes: 1024 * 1024,
};

let workDir: string;
let dest: string;

beforeEach(async () => {
  workDir = await mkdtemp(path.join(os.tmpdir(), 'webguard-extractor-test-'));
  // Nest the destination so a traversal one or two levels up would land inside workDir.
  dest = path.join(workDir, 'a', 'b', 'out');
});

afterEach(async () => {
  await rm(workDir, { recursive: true, force: true });
});

async function zipFile(entries: ZipEntrySpec[]): Promise<string> {
  const file = path.join(workDir, `archive-${Math.random().toString(36).slice(2)}.zip`);
  await writeFile(file, buildZip(entries));
  return file;
}

async function listTree(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { recursive: true, withFileTypes: true });
  return entries
    .filter((e) => e.isFile())
    .map((e) => path.relative(dir, path.join(e.parentPath, e.name)).split(path.sep).join('/'))
    .sort();
}

describe('ExtractorService', () => {
  it('extracts a valid archive into the destination tree', async () => {
    const result = await new ExtractorService(defaults).extract(fixture('valid-site.zip'), dest);
    expect(result).toMatchObject({ filesExtracted: 3, skippedEntries: 0 });
    expect(await listTree(dest)).toEqual(['index.html', 'src/app.js', 'src/lib/util.js']);
    expect(await readFile(path.join(dest, 'src/lib/util.js'), 'utf8')).toContain(
      'export const add',
    );
    expect(result.totalBytes).toBeGreaterThan(0);
  });

  it('refuses a zip-slip entry and writes nothing outside the destination', async () => {
    const error = await new ExtractorService(defaults)
      .extract(fixture('zip-slip.zip'), dest)
      .catch((err: unknown) => err);
    expect(error).toBeInstanceOf(ExtractionError);
    expect((error as Error).message).toMatch(/unsafe path/i);
    expect(existsSync(path.join(workDir, 'a', 'webguard-zip-slip-pwned.txt'))).toBe(false);
    expect(existsSync(path.join(workDir, 'webguard-zip-slip-pwned.txt'))).toBe(false);
    expect(existsSync(path.join(os.tmpdir(), 'webguard-zip-slip-pwned.txt'))).toBe(false);
  });

  it('refuses absolute-path entries', async () => {
    const file = await zipFile([{ name: '/etc/webguard-abs.txt', data: 'x' }]);
    await expect(new ExtractorService(defaults).extract(file, dest)).rejects.toThrow(
      /unsafe path/i,
    );
  });

  it('skips symlinks and special files instead of creating them', async () => {
    const file = await zipFile([
      { name: 'ok.txt', data: 'fine', unixMode: 0o100644 },
      { name: 'evil-link', data: '/etc/passwd', unixMode: 0o120777 },
      { name: 'fifo', data: '', unixMode: 0o010644 },
    ]);
    const result = await new ExtractorService(defaults).extract(file, dest);
    expect(result).toMatchObject({ filesExtracted: 1, skippedEntries: 2 });
    expect(await listTree(dest)).toEqual(['ok.txt']);
  });

  it('fails when the entry count exceeds the cap', async () => {
    const file = await zipFile(
      Array.from({ length: 5 }, (_, i) => ({ name: `f${i}.txt`, data: 'x' })),
    );
    await expect(
      new ExtractorService({ ...defaults, maxFiles: 3 }).extract(file, dest),
    ).rejects.toThrow(/too many entries/i);
  });

  it('fails when total uncompressed size exceeds the cap', async () => {
    const file = await zipFile([
      { name: 'a.txt', data: 'a'.repeat(600) },
      { name: 'b.txt', data: 'b'.repeat(600) },
    ]);
    await expect(
      new ExtractorService({ ...defaults, maxTotalBytes: 1000 }).extract(file, dest),
    ).rejects.toThrow(/maximum uncompressed size/i);
  });

  it('fails on a high compression ratio (zip bomb)', async () => {
    // 10 MiB of zeros deflates to ~10 KiB: a ~1000:1 ratio.
    const file = await zipFile([
      { name: 'bomb.bin', data: Buffer.alloc(10 * 1024 * 1024), deflate: true },
    ]);
    await expect(new ExtractorService(defaults).extract(file, dest)).rejects.toThrow(
      /compression ratio/i,
    );
  });

  it('rejects files that are not ZIP archives', async () => {
    const file = path.join(workDir, 'not.zip');
    await writeFile(file, 'definitely not a zip');
    await expect(new ExtractorService(defaults).extract(file, dest)).rejects.toThrow(
      /invalid or corrupt/i,
    );
  });
});

describe('resolveSafeEntryPath', () => {
  const root = path.resolve(os.tmpdir(), 'webguard-root');

  it.each([
    'src/app.js',
    'a/./b.txt',
    'deep/nested/dir/file.ts',
    '.env',
    '.github/workflows/ci.yml',
  ])('accepts %s', (name) => {
    expect(resolveSafeEntryPath(root, name).startsWith(root + path.sep)).toBe(true);
  });

  it.each([
    '../evil.txt',
    'a/../../evil.txt',
    'a/b/../../../evil.txt',
    '/etc/passwd',
    'C:/Windows/evil.txt',
    'C:evil.txt',
    '..\\evil.txt',
    'file.txt:stream',
    'a/.../b',
    'nul',
    'dir/CON.txt',
    'bad\u0000name',
    '',
    './',
  ])('rejects %j', (name) => {
    expect(() => resolveSafeEntryPath(root, name)).toThrow(ExtractionError);
  });
});
