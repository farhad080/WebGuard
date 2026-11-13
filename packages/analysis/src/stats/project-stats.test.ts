import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { StatsTreeNode } from '@webguard/core';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { fileFromStartScript, ProfilerService } from '../profiler/profiler.js';
import { countLines, countLoc } from './loc.js';
import {
  buildProjectStats,
  buildTree,
  dependencyCountsOf,
  type StatsFinding,
  type StatsRollup,
} from './project-stats.js';

let root: string;

const SERVER_JS = [
  "const express = require('express');", //  1 code
  '', //                                         2 blank
  '/* Product search.', //                       3 comment
  '   Builds SQL from the query. */', //         4 comment
  "app.get('/p', (req, res) => {", //            5 code
  '  // TODO: parameterize', //                  6 comment
  "  db.query('SELECT ' + req.query.q); // x", // 7 code
  '});', //                                      8 code
  '', //                                         (trailing newline)
].join('\n');

const UTIL_PY = ['# helpers', '', 'def f():', '    return 1', ''].join('\n');
const BIG_TS = Array.from({ length: 60 }, (_, i) => `export const v${i} = ${i};`).join('\n');

async function put(rel: string, data: string | Buffer) {
  const file = path.join(root, ...rel.split('/'));
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, data);
}

beforeEach(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), 'webguard-stats-'));
  await put(
    'package.json',
    JSON.stringify({ name: 'x', scripts: { start: 'nodemon --watch src src/server.js' } }),
  );
  await put('yarn.lock', '# yarn lockfile v1\n');
  await put('src/server.js', SERVER_JS);
  await put('src/routes/big.ts', BIG_TS);
  await put('lib/util.py', UTIL_PY);
  await put('public/logo.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 1]));
  await put('data/blob.bin.txt', Buffer.from([1, 2, 0, 3]));
  await put('LICENSE', 'MIT\n');
  await put('vendor.min.js', 'x'.repeat(5000)); // over maxFileBytes below
  await put('node_modules/express/index.js', 'module.exports = {};');
  await put('empty/.keep', '');
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const profiler = () => new ProfilerService({ maxFileBytes: 4096 });

const rollup: StatsRollup = {
  total: 4,
  bySeverity: { critical: 1, high: 1, medium: 1, low: 1, info: 0 },
  byOwaspCategory: { 'A05:2025-Injection': 2, 'A03:2025-Software Supply Chain Failures': 2 },
  riskScore: 48,
  grade: 'C',
  gradeReason: 'risk score 48/100',
};
const findings: StatsFinding[] = [
  {
    filePath: 'src/server.js',
    severity: 'critical',
    owaspCategory: 'A05:2025-Injection',
    detectorId: 'A1-sql-injection',
    evidence: ['req.query.q flows into db.query'],
  },
  {
    filePath: 'src/routes/big.ts',
    severity: 'low',
    owaspCategory: 'A05:2025-Injection',
    detectorId: 'A4-xss',
    evidence: 'x',
  },
  {
    filePath: 'package.json',
    severity: 'high',
    owaspCategory: 'A03:2025-Software Supply Chain Failures',
    detectorId: 'A11-vulnerable-deps',
    evidence: [
      'possible typosquat: "expresss" is 1 edit from "express"; likely intended package: express',
    ],
  },
  {
    filePath: 'package.json',
    severity: 'medium',
    owaspCategory: 'A03:2025-Software Supply Chain Failures',
    detectorId: 'A11-vulnerable-deps',
    evidence: [
      'lodash@4.17.4 (transitive dependency): GHSA-x / CVE-y: Prototype pollution. Fixed in 4.17.21. [source: snapshot]',
      'request@2.88.2 (direct dependency): end-of-life: request is deprecated. [source: snapshot]',
      '@scope/pkg@1.0.0 (direct dependency): GHSA-z: bad. [source: snapshot]',
    ],
  },
];

const find = (node: StatsTreeNode, p: string): StatsTreeNode | undefined =>
  node.path === p ? node : node.children?.map((c) => find(c, p)).find(Boolean);

describe('line counting', () => {
  it('splits code, comment and blank lines', () => {
    expect(countLoc(SERVER_JS, 'javascript')).toEqual({
      code: 4,
      comment: 3,
      blank: 1,
      total: 8,
    });
    expect(countLoc(UTIL_PY, 'python')).toEqual({ code: 2, comment: 1, blank: 1, total: 4 });
    expect(countLoc('<!-- a -->\n<p>x</p> <!-- b -->\n', 'html')).toMatchObject({
      code: 1,
      comment: 1,
    });
    // A glob in a string must not open a block comment for the following lines.
    expect(countLoc("glob('src/**/*.js');\nrun();\n", 'javascript')).toMatchObject({ code: 2 });
    expect(countLines('')).toBe(0);
    expect(countLines('a\nb\n')).toBe(2);
    expect(countLines('a\nb')).toBe(2);
  });

  it('finds the file a start script runs', () => {
    expect(fileFromStartScript('node server.js')).toBe('server.js');
    expect(fileFromStartScript('nodemon --watch src ./src/app.ts')).toBe('src/app.ts');
    expect(fileFromStartScript('npm run build && node dist/index.js')).toBe('dist/index.js');
    expect(fileFromStartScript('react-scripts start')).toBeNull();
  });
});

describe('project statistics from the profiler', () => {
  async function build() {
    const { profile, inventory } = await profiler().profileWithInventory(root);
    const stats = buildProjectStats({
      stage: 'complete',
      zipBytes: 1234,
      extraction: {
        filesExtracted: 10,
        totalBytes: 9999,
        skippedFileCount: 3,
        skippedDirs: ['.git'],
        skippedEntries: 1,
      },
      profile,
      inventory,
      dependencies: { direct: 3, transitive: 40, manifests: ['yarn.lock', 'package.json'] },
      findings,
      rollup,
      scan: {
        startedAt: new Date('2026-11-13T10:00:00Z'),
        finishedAt: new Date('2026-11-13T10:00:02.5Z'),
        rules: ['A1-sql-injection', 'A11-vulnerable-deps'],
        filesParsed: 2,
        parseErrors: 0,
      },
      now: new Date('2026-11-13T10:00:03Z'),
    });
    return { profile, inventory, stats };
  }

  it('counts files, folders, lines of code and the largest/longest files', async () => {
    const { inventory, stats } = await build();
    // node_modules is never descended into; every other directory and file is counted.
    expect([...inventory.folders].sort()).toEqual([
      'data',
      'empty',
      'lib',
      'public',
      'src',
      'src/routes',
    ]);
    expect(stats).toMatchObject({ version: 1, status: 'complete', stage: 'complete' });
    expect(stats.size).toMatchObject({
      files: 10,
      folders: 6,
      zipBytes: 1234,
      unpackedBytes: 9999,
      // JS 4/3/1 + TS 60/0/0 + Python 2/1/1 + JSON 1/0/0
      loc: { code: 67, comment: 4, blank: 2, total: 73 },
    });
    expect(stats.size.largestFiles.map((f) => f.path).slice(0, 2)).toEqual([
      'vendor.min.js',
      'src/routes/big.ts',
    ]);
    expect(stats.size.largestFiles).toHaveLength(5);
    expect(stats.size.largestFiles[0]).toMatchObject({ bytes: 5000, lines: null });
    expect(stats.size.longestFiles.slice(0, 3)).toEqual([
      { path: 'src/routes/big.ts', bytes: expect.any(Number), lines: 60, language: 'typescript' },
      { path: 'src/server.js', bytes: SERVER_JS.length, lines: 8, language: 'javascript' },
      { path: 'lib/util.py', bytes: UTIL_PY.length, lines: 4, language: 'python' },
    ]);
  });

  it('breaks languages down by lines and files, with an honest analysis depth', async () => {
    const { stats } = await build();
    expect(stats.languages.map((l) => [l.language, l.files, l.loc.total])).toEqual([
      ['typescript', 1, 60],
      ['javascript', 1, 8],
      ['python', 1, 4],
      ['json', 1, 1],
    ]);
    const depth = Object.fromEntries(stats.languages.map((l) => [l.language, l.analysisLabel]));
    expect(depth).toEqual({
      typescript: 'full AST analysis',
      javascript: 'full AST analysis',
      python: 'secrets/crypto/deps/config only',
      json: 'secrets/crypto/deps/config only',
    });
    expect(stats.languages[1]!.loc).toEqual({ code: 4, comment: 3, blank: 1, total: 8 });
    expect(stats.stack).toMatchObject({
      entryPoints: ['src/server.js'],
      packageManagers: [{ name: 'yarn', lockfile: 'yarn.lock' }],
    });
    expect(stats.stack!.frameworks.map((f) => f.name)).toContain('Node.js');
  });

  it('reports every skipped file by reason', async () => {
    const { stats } = await build();
    expect(stats.skipped).toEqual({
      ignoredDirFiles: 4, // 3 at extraction + node_modules/express/index.js at profiling
      ignoredDirs: ['.git'],
      binary: 2, // logo.png (extension), blob.bin.txt (NUL bytes)
      tooLarge: 1, // vendor.min.js
      unrecognized: 3, // yarn.lock, LICENSE, empty/.keep
      unsupportedEntries: 1,
    });
  });

  it('builds the folder tree with file and finding counts and the worst severity', async () => {
    const { stats } = await build();
    const tree = stats.tree!;
    expect(tree).toMatchObject({ path: '', type: 'dir', files: 10, findings: 4 });
    expect(tree.worstSeverity).toBe('critical');
    // Directories first, then files, by name.
    expect(tree.children!.map((c) => c.name)).toEqual([
      'data',
      'empty',
      'lib',
      'public',
      'src',
      'LICENSE',
      'package.json',
      'vendor.min.js',
      'yarn.lock',
    ]);
    expect(find(tree, 'src')).toMatchObject({ files: 2, findings: 2, worstSeverity: 'critical' });
    expect(find(tree, 'src/routes')).toMatchObject({
      files: 1,
      findings: 1,
      worstSeverity: 'low',
    });
    expect(find(tree, 'src/server.js')).toMatchObject({
      type: 'file',
      files: 1,
      findings: 1,
      worstSeverity: 'critical',
      language: 'javascript',
    });
    expect(find(tree, 'package.json')).toMatchObject({ findings: 2, worstSeverity: 'high' });
    expect(find(tree, 'lib')).toMatchObject({ files: 1, findings: 0, worstSeverity: null });
    expect(find(tree, 'empty')).toMatchObject({ files: 1 });
  });

  it('summarizes dependencies from A11 and security from the rollup', async () => {
    const { stats } = await build();
    expect(stats.dependencies).toEqual({
      direct: 3,
      transitive: 40,
      total: 43,
      vulnerable: 2, // lodash, @scope/pkg
      outdated: 1, // request (end-of-life)
      typosquats: [{ name: 'expresss', target: 'express' }],
      manifests: ['package.json', 'yarn.lock'],
    });
    expect(stats.security).toMatchObject({
      total: 4,
      riskScore: 48,
      grade: 'C',
      bySeverity: rollup.bySeverity,
      topFiles: [
        { path: 'package.json', findings: 2, worstSeverity: 'high' },
        { path: 'src/server.js', findings: 1, worstSeverity: 'critical' },
        { path: 'src/routes/big.ts', findings: 1, worstSeverity: 'low' },
      ],
    });
    expect(stats.scan).toEqual({
      startedAt: '2026-11-13T10:00:00.000Z',
      finishedAt: '2026-11-13T10:00:02.500Z',
      durationMs: 2500,
      rules: ['A1-sql-injection', 'A11-vulnerable-deps'],
      filesParsed: 2,
      parseErrors: 0,
    });
  });

  it('produces partial stats from the stages that finished', () => {
    const stats = buildProjectStats({
      stage: 'extraction',
      zipBytes: 500,
      extraction: {
        filesExtracted: 7,
        totalBytes: 2048,
        skippedFileCount: 12,
        skippedDirs: ['node_modules'],
        skippedEntries: 0,
      },
      scan: { startedAt: new Date(0), finishedAt: new Date(1000), rules: [] },
    });
    expect(stats).toMatchObject({
      status: 'partial',
      stage: 'extraction',
      size: { files: 7, folders: null, zipBytes: 500, unpackedBytes: 2048, loc: null },
      languages: [],
      stack: null,
      tree: null,
      dependencies: null,
      security: null,
      skipped: { ignoredDirFiles: 12, ignoredDirs: ['node_modules'] },
      scan: { durationMs: 1000 },
    });
  });
});

describe('folder tree caps', () => {
  const files = Array.from({ length: 30 }, (_, i) => ({
    path: `a/b/c/f${String(i).padStart(2, '0')}.js`,
    bytes: 1,
    language: 'javascript' as const,
    kind: 'source' as const,
    lines: 1,
    loc: null,
  }));
  const folders = ['a', 'a/b', 'a/b/c'];
  const hits = [{ filePath: 'a/b/c/f29.js', severity: 'high' as const }];

  it('collapses directories past maxDepth, keeping exact counts', () => {
    const tree = buildTree({ files, folders }, hits, {
      maxDepth: 2,
      maxNodes: 1000,
      maxChildren: 100,
    });
    const b = find(tree, 'a/b')!;
    expect(b.children).toEqual([]);
    expect(b.omitted).toEqual({ dirs: 1, files: 0 });
    expect(b).toMatchObject({ files: 30, findings: 1, worstSeverity: 'high' });
  });

  it('caps children per directory and total nodes', () => {
    let tree = buildTree({ files, folders }, hits, {
      maxDepth: 10,
      maxNodes: 1000,
      maxChildren: 10,
    });
    let c = find(tree, 'a/b/c')!;
    expect(c.children).toHaveLength(10);
    expect(c.omitted).toEqual({ dirs: 0, files: 20 });

    tree = buildTree({ files, folders }, hits, { maxDepth: 10, maxNodes: 8, maxChildren: 100 });
    c = find(tree, 'a/b/c')!;
    // root + a + b + c = 4 nodes, then 4 files fit.
    expect(c.children).toHaveLength(4);
    expect(c.omitted).toEqual({ dirs: 0, files: 26 });
    expect(c.findings).toBe(1);
  });

  it('counts direct vs transitive dependency names', () => {
    expect(
      dependencyCountsOf([
        { name: 'express', direct: true, file: 'package-lock.json', declaredFile: 'package.json' },
        { name: 'express', direct: true, file: 'package.json' },
        { name: 'accepts', direct: false, file: 'package-lock.json' },
        { name: 'debug', direct: false, file: 'package-lock.json' },
      ]),
    ).toEqual({ direct: 1, transitive: 2, manifests: ['package-lock.json', 'package.json'] });
  });
});
