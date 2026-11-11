import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { OwaspCategory } from '@webguard/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { materializeMiniExpress } from '../../test/fixture-project.js';
import type { ParsedFile } from '../ast/types.js';
import { parseSourceFiles } from '../parse-project.js';
import { ProfilerService } from '../profiler/profiler.js';
import { createDetectionContext } from './context.js';
import { dedupeFindings } from './dedupe.js';
import { createDefaultDetectorRegistry } from './detectors/index.js';
import { DetectionEngine, type EngineLogger } from './engine.js';
import { DetectorRegistry } from './registry.js';
import {
  combineConfidence,
  confidenceBand,
  countFindings,
  filterByConfidence,
  maxSeverity,
} from './scoring.js';
import { getSnippet } from './snippet.js';
import type { DetectionContext, Detector, Technique, ValidatedFinding } from './types.js';

const silent: EngineLogger = { warn: () => undefined };

let root: string;
let ctx: DetectionContext;

beforeAll(async () => {
  root = await materializeMiniExpress();
  const profile = await new ProfilerService().profile(root);
  const files: ParsedFile[] = [];
  for await (const f of parseSourceFiles(root, profile)) files.push(f);
  ctx = createDetectionContext({ rootDir: root, profile, files });
});

afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

function detector(
  id: string,
  technique: Technique,
  run: Detector['run'],
  owaspCategory: OwaspCategory = 'A03:2021-Injection',
): Detector {
  return {
    id,
    title: id,
    owaspCategory,
    technique,
    explanation: `${id} explanation`,
    fixSuggestion: `${id} fix`,
    run,
  };
}

function finding(overrides: Partial<ValidatedFinding> = {}): ValidatedFinding {
  return {
    detectorId: 'a',
    owaspCategory: 'A03:2021-Injection',
    severity: 'high',
    confidence: 0.6,
    filePath: 'src/routes/users.js',
    lineStart: 8,
    lineEnd: 8,
    snippet: 'line 8',
    evidence: 'evidence from a',
    explanation: 'explanation',
    fixSuggestion: 'fix',
    ...overrides,
  };
}

describe('DetectionEngine', () => {
  it('runs detectors in stage order: pattern → ast → dataflow → dependency → config', async () => {
    const seen: string[] = [];
    const record = (id: string) => () => {
      seen.push(id);
      return [];
    };
    // Registered deliberately out of order.
    const registry = new DetectorRegistry([
      detector('cfg', 'config', record('cfg')),
      detector('dep', 'dependency', record('dep')),
      detector('flow', 'dataflow', record('flow')),
      detector('ast-1', 'ast', record('ast-1')),
      detector('pat', 'pattern', record('pat')),
      detector('ast-2', 'ast', record('ast-2')),
    ]);
    const result = await new DetectionEngine(registry, { logger: silent }).run(ctx);
    expect(seen).toEqual(['pat', 'ast-1', 'ast-2', 'flow', 'dep', 'cfg']);
    expect(result.executed).toEqual(seen);
  });

  it('isolates a throwing detector: it is recorded and the others still run', async () => {
    const good = detector('good', 'config', (c) => [
      {
        detectorId: 'good',
        owaspCategory: 'A03:2021-Injection',
        severity: 'low',
        confidence: 0.9,
        filePath: 'src/routes/users.js',
        lineStart: 8,
        lineEnd: 8,
        snippet: c.snippet('src/routes/users.js', 8),
        evidence: 'ok',
      },
    ]);
    const registry = new DetectorRegistry([
      detector('sync-throw', 'pattern', () => {
        throw new Error('kaboom');
      }),
      detector('async-reject', 'ast', async () => {
        throw new Error('async kaboom');
      }),
      detector('not-array', 'dataflow', () => 'nope' as never),
      good,
    ]);
    const warnings: string[] = [];
    const result = await new DetectionEngine(registry, {
      logger: { warn: (m) => warnings.push(m) },
    }).run(ctx);

    expect(result.executed).toEqual(['sync-throw', 'async-reject', 'not-array', 'good']);
    expect(result.detectorErrors).toEqual([
      { detectorId: 'sync-throw', stage: 'pattern', message: 'threw: kaboom' },
      { detectorId: 'async-reject', stage: 'ast', message: 'threw: async kaboom' },
      { detectorId: 'not-array', stage: 'dataflow', message: 'returned a non-array result' },
    ]);
    expect(warnings).toHaveLength(3);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      detectorId: 'good',
      explanation: 'good explanation',
      fixSuggestion: 'good fix',
    });
  });

  it('validates findings: drops bad ones, clamps confidence, fills snippet, enforces detector id', async () => {
    const registry = new DetectorRegistry([
      detector('sloppy', 'pattern', () => [
        // valid, but with sloppy fields
        {
          detectorId: 'someone-else',
          owaspCategory: 'A03:2021-Injection',
          severity: 'medium',
          confidence: 7,
          filePath: 'src/routes/users.js',
          lineStart: 7,
          lineEnd: 7,
          snippet: '',
          evidence: 'x',
        },
        // invalid: unknown file, bad lines, bad severity
        { ...base(), filePath: 'nope.js' },
        { ...base(), filePath: '../../etc/passwd' },
        { ...base(), lineStart: 0 },
        { ...base(), severity: 'catastrophic' as never },
      ]),
    ]);
    const result = await new DetectionEngine(registry, { logger: silent }).run(ctx);
    expect(result.findings).toEqual([
      expect.objectContaining({
        detectorId: 'sloppy',
        confidence: 1,
        snippet: '  const name = req.body.name;',
      }),
    ]);
    expect(result.detectorErrors).toEqual([
      {
        detectorId: 'sloppy',
        stage: 'pattern',
        message: expect.stringMatching(/^4 invalid finding\(s\) dropped; first: unknown file/),
      },
    ]);

    function base() {
      return {
        detectorId: 'sloppy',
        owaspCategory: 'A03:2021-Injection' as const,
        severity: 'low' as const,
        confidence: 0.5,
        filePath: 'src/routes/users.js',
        lineStart: 1,
        lineEnd: 1,
        snippet: 'x',
        evidence: 'x',
      };
    }
  });
});

describe('example-todo-comment detector', () => {
  it('flags a TODO SECURITY comment with the exact file, line, and snippet', async () => {
    const result = await new DetectionEngine(createDefaultDetectorRegistry(), {
      logger: silent,
    }).run(ctx);
    const findings = dedupeFindings(result.findings);
    expect(result.detectorErrors).toEqual([]);
    expect(findings).toEqual([
      {
        detectorId: 'example-todo-comment',
        owaspCategory: 'A04:2021-Insecure Design',
        severity: 'info',
        confidence: 1,
        filePath: 'src/server.ts',
        lineStart: 10,
        lineEnd: 10,
        snippet: '// TODO SECURITY: add rate limiting to /users before launch',
        explanation: expect.stringContaining('TODO SECURITY'),
        fixSuggestion: expect.any(String),
        contributingDetectors: ['example-todo-comment'],
        evidence: [expect.stringContaining('TODO SECURITY')],
      },
    ]);
  });

  it('matches common comment styles but not plain prose or code', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'webguard-todo-'));
    try {
      const lines = [
        '# TODO SECURITY: rotate keys', // 1 yes
        '/* todo(security) validate */', // 2 yes
        ' * TODO: Security review', // 3 yes
        '<!-- TODO SECURITY csp -->', // 4 yes
        'const msg = "TODO SECURITY";', // 5 no (string, not comment)
        '// TODO: refactor', // 6 no (not security)
      ];
      await writeFile(path.join(dir, 'notes.py'), lines.join('\n'));
      const profile = await new ProfilerService().profile(dir);
      const localCtx = createDetectionContext({ rootDir: dir, profile, files: [] });
      const found = await createDefaultDetectorRegistry()
        .get('example-todo-comment')!
        .run(localCtx);
      expect(found.map((f) => f.lineStart)).toEqual([1, 2, 3, 4]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('dedupeFindings', () => {
  it('collapses duplicates from the same detector at the same place', () => {
    const out = dedupeFindings([
      finding({ confidence: 0.5, evidence: 'first' }),
      finding({ confidence: 0.9, severity: 'critical', evidence: 'second' }),
      finding({ confidence: 0.7, evidence: 'first' }),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      detectorId: 'a',
      severity: 'critical',
      confidence: 0.9,
      contributingDetectors: ['a'],
      evidence: ['first', 'second'],
    });
  });

  it('correlates two detectors on the same line: highest severity, combined confidence', () => {
    const out = dedupeFindings([
      finding({
        detectorId: 'sqli-pattern',
        severity: 'medium',
        confidence: 0.6,
        evidence: 'regex hit',
      }),
      finding({
        detectorId: 'sqli-dataflow',
        severity: 'critical',
        confidence: 0.6,
        evidence: 'taint path',
      }),
    ]);
    expect(out).toEqual([
      expect.objectContaining({
        detectorId: 'sqli-dataflow', // primary = most severe
        severity: 'critical',
        confidence: 0.84, // 1 - 0.4 * 0.4
        contributingDetectors: ['sqli-dataflow', 'sqli-pattern'],
        evidence: ['taint path', 'regex hit'],
      }),
    ]);
  });

  it('keeps different OWASP categories and different lines separate', () => {
    const out = dedupeFindings([
      finding({ detectorId: 'sqli' }),
      finding({ detectorId: 'secret', owaspCategory: 'A02:2021-Cryptographic Failures' }),
      finding({ detectorId: 'sqli', lineStart: 13, lineEnd: 13 }),
    ]);
    expect(out).toHaveLength(3);
  });

  it('sorts by severity, then file, then line', () => {
    const out = dedupeFindings([
      finding({ detectorId: 'x', severity: 'low', filePath: 'a.js', lineStart: 1 }),
      finding({ detectorId: 'x', severity: 'critical', filePath: 'b.js', lineStart: 9 }),
      finding({ detectorId: 'x', severity: 'critical', filePath: 'b.js', lineStart: 2 }),
    ]);
    expect(out.map((f) => `${f.severity}:${f.filePath}:${f.lineStart}`)).toEqual([
      'critical:b.js:2',
      'critical:b.js:9',
      'low:a.js:1',
    ]);
  });
});

describe('scoring helpers', () => {
  it('filters by confidence and bands it', () => {
    const items = [{ confidence: 0.2 }, { confidence: 0.5 }, { confidence: 0.95 }];
    expect(filterByConfidence(items, 0.5)).toEqual([{ confidence: 0.5 }, { confidence: 0.95 }]);
    expect(items.map((i) => confidenceBand(i.confidence))).toEqual(['low', 'medium', 'high']);
  });

  it('combines confidence with noisy-OR and picks the max severity', () => {
    expect(combineConfidence([0.5, 0.5])).toBe(0.75);
    expect(combineConfidence([1, 0.3])).toBe(1);
    expect(maxSeverity(['low', 'high', 'medium'])).toBe('high');
  });

  it('counts findings by severity and OWASP category', () => {
    expect(
      countFindings([
        { severity: 'high', owaspCategory: 'A03:2021-Injection' },
        { severity: 'high', owaspCategory: 'A03:2021-Injection' },
        { severity: 'info', owaspCategory: 'A04:2021-Insecure Design' },
      ]),
    ).toEqual({
      total: 3,
      bySeverity: { critical: 0, high: 2, medium: 0, low: 0, info: 1 },
      byOwaspCategory: { 'A03:2021-Injection': 2, 'A04:2021-Insecure Design': 1 },
    });
  });
});

describe('getSnippet', () => {
  const text = 'one\ntwo\r\nthree\nfour\nfive';

  it('returns the exact lines of a range', () => {
    expect(getSnippet(text, 2)).toBe('two');
    expect(getSnippet(text, 2, 3)).toBe('two\nthree');
  });

  it('supports context lines and clamps to the file', () => {
    expect(getSnippet(text, 1, 1, { contextLines: 1 })).toBe('one\ntwo');
    expect(getSnippet(text, 5, 99)).toBe('five');
  });

  it('truncates very long ranges', () => {
    expect(getSnippet(text, 1, 5, { maxLines: 2 })).toBe('one\ntwo\n…');
    expect(getSnippet('x'.repeat(50), 1, 1, { maxChars: 10 })).toBe(`${'x'.repeat(10)}…`);
  });
});

describe('DetectorRegistry', () => {
  it('includes the built-in example detector and refuses duplicate ids', () => {
    const registry = createDefaultDetectorRegistry();
    expect(registry.list().map((d) => d.id)).toContain('example-todo-comment');
    expect(() => registry.register(registry.get('example-todo-comment')!)).toThrow(
      /already registered/,
    );
  });

  it('returns a fresh copy, so callers can add detectors without touching the built-ins', () => {
    const a = createDefaultDetectorRegistry();
    a.register(detector('extra', 'pattern', () => []));
    expect(createDefaultDetectorRegistry().get('extra')).toBeUndefined();
  });
});
