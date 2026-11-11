import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { ParsedFile } from '../../ast/types.js';
import { OsvAdvisorySource, SnapshotAdvisorySource } from '../../deps/advisories.js';
import { editDistance } from '../../deps/dependencies.js';
import { parseSourceFiles } from '../../parse-project.js';
import { ProfilerService } from '../../profiler/profiler.js';
import { createDetectionContext } from '../context.js';
import { dedupeFindings } from '../dedupe.js';
import { DetectionEngine } from '../engine.js';
import { INFORMATIONAL_NOTES } from '../informational.js';
import { DetectorRegistry } from '../registry.js';
import type { FindingDraft } from '../types.js';
import { createDependencyDetector } from './a11-vulnerable-deps.js';
import { createDefaultDetectorRegistry } from './index.js';

const fixture = (name: string) =>
  fileURLToPath(new URL(`../../../test/fixtures/${name}`, import.meta.url));

async function scan(
  root: string,
  registry = createDefaultDetectorRegistry(),
): Promise<FindingDraft[]> {
  const profile = await new ProfilerService().profile(root);
  const files: ParsedFile[] = [];
  for await (const f of parseSourceFiles(root, profile)) files.push(f);
  const result = await new DetectionEngine(registry).run(
    createDetectionContext({ rootDir: root, profile, files }),
  );
  expect(result.detectorErrors).toEqual([]);
  return dedupeFindings(result.findings);
}

const by = (findings: FindingDraft[], id: string) =>
  findings.filter((f) => f.detectorId === id || f.contributingDetectors.includes(id));
const fmt = (f: FindingDraft) => `${f.severity} ${f.filePath}:${f.lineStart}`;

describe('A7-sensitive-file-exposure', () => {
  it("flags package.json.bak and other sensitive files under express.static/serveIndex('ftp')", async () => {
    const a7 = by(await scan(fixture('exposure')), 'A7-sensitive-file-exposure');
    const backup = a7.find((f) => f.filePath === 'ftp/package.json.bak')!;
    expect(backup).toMatchObject({
      owaspCategory: 'A02:2025-Security Misconfiguration',
      severity: 'high',
      confidence: 0.85,
    });
    expect(backup.evidence[0]).toBe(
      'backup file "package.json.bak" is publicly served (served by serveIndex(\'ftp\') at server.js:19)',
    );
    expect(a7.map(fmt)).toEqual(
      expect.arrayContaining([
        'high ftp/acquisitions.md:1', // #12 confidential document
        'high ftp/coupons_2013.md.bak:1', // #16
        'high ftp/incident-support.kdbx:1',
        'high ftp/package.json.bak:1', // #18
      ]),
    );
    expect(a7.some((f) => f.filePath === 'ftp/legal.md')).toBe(false);
    expect(a7.some((f) => f.filePath.startsWith('public/'))).toBe(false);
  });

  it('flags a null-byte-bypassable suffix filter on the file server (#38)', async () => {
    const [f] = by(await scan(fixture('exposure')), 'A7-sensitive-file-exposure').filter(
      (x) => x.filePath === 'routes/fileServer.js',
    );
    expect(f).toMatchObject({ severity: 'high', lineStart: 18 });
    expect(f!.evidence[0]).toContain('%2500.md');
    expect(f!.evidence[0]).toContain('null byte is stripped only after the suffix check');
  });

  it('flags directory listing (correlated with A12) and JSONP as low-confidence best effort (#19)', async () => {
    const findings = await scan(fixture('exposure'));
    const listing = findings.find((f) => f.filePath === 'server.js' && f.lineStart === 19)!;
    expect(listing.severity).toBe('medium');
    expect(listing.contributingDetectors.sort()).toEqual([
      'A12-security-misconfig',
      'A7-sensitive-file-exposure',
    ]);
    const jsonp = by(findings, 'A7-sensitive-file-exposure').find(
      (f) => f.filePath === 'routes/currentUser.js',
    )!;
    expect(jsonp.confidence).toBe(0.35);
    expect(jsonp.explanation).toMatch(/manual or dynamic review/);
  });
});

describe('A11-vulnerable-deps', () => {
  it('reports outdated sanitize-html, typosquats, EOL and transitive vulns, and nothing for normal deps', async () => {
    const a11 = by(await scan(fixture('deps')), 'A11-vulnerable-deps');
    const line = (f: FindingDraft) =>
      `${f.severity} ${f.confidence} ${f.filePath}:${f.lineStart} ${f.evidence[0]!.split(':')[0]}`;
    expect(a11.map(line).sort()).toEqual([
      'critical 0.9 package-lock.json:23 minimist@1.2.5 (transitive dependency)',
      'high 0.6 package.json:6 possible typosquat',
      'high 0.65 frontend/package.json:6 possible typosquat',
      'high 0.9 package.json:12 sanitize-html@1.4.2 (direct dependency)',
      'high 0.9 package.json:8 express-jwt@0.1.3 (direct dependency)',
      'medium 0.8 package.json:11 request@2.88.2 (direct dependency)',
    ]);
    const sanitize = a11.find((f) => f.evidence[0]!.startsWith('sanitize-html'))!;
    expect(sanitize.evidence[0]).toContain('CVE-2016-1000237');
    expect(sanitize.evidence[0]).toContain('Fixed in 1.4.3');
    expect(sanitize.fixSuggestion).toContain('sanitize-html@^1.4.3');
    expect(
      a11.find((f) => f.filePath === 'package.json' && f.lineStart === 6)!.evidence[0],
    ).toContain('likely intended package: epilogue');
    expect(a11.find((f) => f.filePath === 'frontend/package.json')!.evidence[0]).toContain(
      'likely intended package: ngx-cookie',
    );
    // express, lodash 4.17.21, preact (allowlisted, 1 edit from react), @angular/core, rxjs: no findings
    expect(a11.some((f) => /\b(express|lodash|preact|rxjs)@/.test(f.evidence[0]!))).toBe(false);
  });

  it('falls back to the minimum of a package.json range when there is no lockfile', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'webguard-deps-'));
    try {
      await writeFile(
        path.join(dir, 'package.json'),
        JSON.stringify({ dependencies: { 'sanitize-html': '^1.4.2' } }, null, 2),
      );
      const [f] = by(await scan(dir), 'A11-vulnerable-deps');
      expect(f).toMatchObject({ confidence: 0.7, filePath: 'package.json', lineStart: 3 });
      expect(f!.evidence[0]).toContain('minimum of "^1.4.2"; resolved version unknown');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('works offline by default and accepts a pluggable live source', async () => {
    const calls: string[] = [];
    const osv = new OsvAdvisorySource({
      allowNetwork: true,
      fetch: async (url, init) => {
        calls.push(url);
        const body = JSON.parse(init.body) as { queries: Array<{ package: { name: string } }> };
        return {
          ok: true,
          status: 200,
          json: async () => ({
            results: body.queries.map((q) =>
              q.package.name === 'express' ? { vulns: [{ id: 'GHSA-test-only' }] } : {},
            ),
          }),
        };
      },
    });
    const registry = new DetectorRegistry([
      createDependencyDetector({ sources: [new SnapshotAdvisorySource([]), osv] }),
    ]);
    const findings = await scan(fixture('deps'), registry);
    expect(calls).toEqual(['https://api.osv.dev/v1/querybatch']);
    expect(
      findings.some(
        (f) =>
          f.evidence[0]!.includes('GHSA-test-only') && f.evidence[0]!.includes('[source: osv]'),
      ),
    ).toBe(true);
  });

  it('never calls the network unless explicitly allowed', async () => {
    let called = false;
    const osv = new OsvAdvisorySource({
      fetch: async () => {
        called = true;
        throw new Error('no');
      },
    });
    const result = await osv.lookup([{ name: 'express', version: '4.0.0' }]);
    expect(called).toBe(false);
    expect(result.warnings[0]).toMatch(/network access is disabled/);
  });

  it('computes edit distance', () => {
    expect(editDistance('ngy-cookie', 'ngx-cookie')).toBe(1);
    expect(editDistance('lodahs', 'lodash')).toBe(2);
    expect(editDistance('express', 'react', 2)).toBe(3);
  });
});

describe('A12-security-misconfig', () => {
  it('flags errorhandler() without an environment check (#36), missing headers, and listing', async () => {
    const a12 = by(await scan(fixture('exposure')), 'A12-security-misconfig');
    expect(a12.map((f) => `${f.severity} ${f.lineStart} ${f.evidence[0]!.slice(0, 40)}`)).toEqual([
      'high 31 errorhandler() middleware is enabled wit',
      'medium 11 no helmet() and no Content-Security-Poli',
      'medium 19 directory listing enabled via serveIndex',
      'medium 26 POST /file-upload still accepts XML uplo',
      'medium 28 POST /b2b/v1/orders is marked deprecated',
      'low 33 hygiene: no /.well-known/security.txt fi',
    ]);
    const headers = a12.find((f) => f.lineStart === 11)!;
    expect(headers.explanation).toMatch(/invisible to source analysis/);
  });

  it('flags the deprecated XML upload interface (#37) with low confidence and XXE note', async () => {
    const a12 = by(await scan(fixture('exposure')), 'A12-security-misconfig');
    const upload = a12.find((f) => f.lineStart === 26)!;
    expect(upload.confidence).toBe(0.4);
    expect(upload.evidence[0]).toContain('noent: true');
  });

  it('reports a missing security.txt as a low hygiene note (#35)', async () => {
    const note = by(await scan(fixture('exposure')), 'A12-security-misconfig').find(
      (f) => f.severity === 'low',
    )!;
    expect(note).toMatchObject({ filePath: 'server.js', confidence: 0.7 });
  });

  it('does not flag NODE_ENV-gated error output, helmet apps, or projects with security.txt', async () => {
    expect(await scan(fixture('exposure-safe'))).toEqual([]);
  });

  it('flags an ungated err.stack response', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'webguard-err-'));
    try {
      await writeFile(
        path.join(dir, 'app.js'),
        [
          "const express = require('express');",
          "const helmet = require('helmet');",
          'const app = express();',
          'app.use(helmet());',
          'app.use((err, req, res, next) => {',
          '  res.status(500).send({ message: err.message, stack: err.stack });',
          '});',
          '// security.txt is served by the CDN',
        ].join('\n'),
      );
      const a12 = by(await scan(dir), 'A12-security-misconfig');
      expect(a12.map((f) => [f.severity, f.lineStart])).toEqual([['high', 6]]);
      expect(a12[0]!.evidence[0]).toContain('err.stack');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('informational notes', () => {
  it('lists the documented non-detectable challenges', () => {
    expect(INFORMATIONAL_NOTES.flatMap((n) => n.references)).toEqual([
      'Juice Shop #15',
      'Juice Shop #17',
      'Juice Shop #33',
      'Juice Shop #34',
    ]);
  });
});
