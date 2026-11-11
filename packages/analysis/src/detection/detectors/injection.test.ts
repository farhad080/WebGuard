import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import type { ParsedFile } from '../../ast/types.js';
import { parseSourceFiles } from '../../parse-project.js';
import { ProfilerService } from '../../profiler/profiler.js';
import { createDetectionContext } from '../context.js';
import { dedupeFindings } from '../dedupe.js';
import { DetectionEngine } from '../engine.js';
import type { FindingDraft } from '../types.js';
import { createDefaultDetectorRegistry } from './index.js';

const ROOT = fileURLToPath(new URL('../../../test/fixtures/injection', import.meta.url));
let findings: FindingDraft[];

beforeAll(async () => {
  const profile = await new ProfilerService().profile(ROOT);
  const files: ParsedFile[] = [];
  for await (const f of parseSourceFiles(ROOT, profile)) files.push(f);
  expect(files.filter((f) => f.parseError)).toEqual([]);
  const result = await new DetectionEngine(createDefaultDetectorRegistry()).run(
    createDetectionContext({ rootDir: ROOT, profile, files }),
  );
  expect(result.detectorErrors).toEqual([]);
  findings = dedupeFindings(result.findings);
});

// Scoped to the injection detectors: other detectors (e.g. A4 XSS) may legitimately flag
// the same fixtures and are tested on their own.
const INJECTION = /^A[123]-/;
const inFile = (path: string) =>
  findings.filter((f) => f.filePath === path && INJECTION.test(f.detectorId));
const summary = (f: FindingDraft) => ({
  detectorId: f.detectorId,
  owaspCategory: f.owaspCategory,
  severity: f.severity,
  confidence: f.confidence,
  line: f.lineStart,
});

describe('A1-sql-injection', () => {
  it('flags the Juice Shop login query (req.body.email in a template literal)', () => {
    const [f] = inFile('routes/sqli/login.ts');
    expect(summary(f!)).toEqual({
      detectorId: 'A1-sql-injection',
      owaspCategory: 'A05:2025-Injection',
      severity: 'critical',
      confidence: 0.9,
      line: 9,
    });
    expect(f!.evidence[0]).toContain("`req.body.email || ''` ← req.body.email");
    expect(f!.snippet).toContain("WHERE email = '${req.body.email || ''}'");
    expect(f!.explanation).toMatch(/SQL/);
    expect(f!.fixSuggestion).toMatch(/parameterized/i);
  });

  it('traces search criteria through a ternary and a reassignment', () => {
    const [f] = inFile('routes/sqli/search.ts');
    expect(summary(f!)).toMatchObject({ severity: 'critical', confidence: 0.9, line: 9 });
    expect(f!.evidence[0]).toContain('`criteria` ← criteria ← req.query.q');
  });

  it('traces destructured input into a concatenated db.all() query', () => {
    expect(inFile('routes/sqli/raw-concat.js').map(summary)).toEqual([
      expect.objectContaining({ severity: 'critical', confidence: 0.9, line: 8 }),
    ]);
  });

  it('reports dynamic SQL with an unprovable source at medium confidence', () => {
    expect(inFile('routes/sqli/unproven.js').map(summary)).toEqual([
      expect.objectContaining({ severity: 'high', confidence: 0.5, line: 5 }),
    ]);
  });

  it('does not flag parameterized, numeric-cast, or escaped queries', () => {
    expect(inFile('routes/sqli/login-safe.ts')).toEqual([]);
  });

  it('does not flag constant/enum/env-only queries or ORM builder calls', () => {
    expect(inFile('routes/sqli/constant-only.ts')).toEqual([]);
  });
});

describe('A2-nosql-injection', () => {
  it('flags db.reviews.update(req.body, …): the whole body as the selector', () => {
    const [f] = inFile('routes/nosql/whole-body.js');
    expect(summary(f!)).toEqual({
      detectorId: 'A2-nosql-injection',
      owaspCategory: 'A05:2025-Injection',
      severity: 'high',
      confidence: 0.6,
      line: 6,
    });
    expect(f!.evidence[0]).toMatch(/entire query selector/);
  });

  it('flags the Juice Shop review update with an uncoerced client id', () => {
    const [f] = inFile('routes/nosql/updateProductReviews.ts');
    expect(summary(f!)).toMatchObject({ severity: 'high', confidence: 0.6, line: 7 });
    expect(f!.evidence[0]).toContain('"_id" selector');
  });

  it('flags $where JavaScript built from a route param (critical, high confidence)', () => {
    const [f] = inFile('routes/nosql/showProductReviews.ts');
    expect(summary(f!)).toMatchObject({ severity: 'critical', confidence: 0.8, line: 8 });
    expect(f!.evidence[0]).toContain('$where');
  });

  it('does not flag coerced scalars, Array#find, or route-param equality', () => {
    expect(inFile('routes/nosql/safe.ts')).toEqual([]);
  });
});

describe('A3-ssti', () => {
  it('flags eval("\'" + user.username + "\'") as critical', () => {
    const [f] = inFile('routes/ssti/greeting.js');
    expect(summary(f!)).toEqual({
      detectorId: 'A3-ssti',
      owaspCategory: 'A05:2025-Injection',
      severity: 'critical',
      confidence: 0.85,
      line: 3,
    });
  });

  it('flags the Juice Shop profile eval and the pug.compile fed by it', () => {
    const lines = inFile('routes/ssti/userProfile.ts').map(summary);
    expect(lines).toEqual([
      expect.objectContaining({ severity: 'critical', line: 14 }), // eval(code)
      expect.objectContaining({ severity: 'critical', line: 18 }), // pug.compile(template)
    ]);
    expect(inFile('routes/ssti/userProfile.ts')[0]!.evidence[0]).toContain(
      '`code` ← code ← username ← user?.username',
    );
  });

  it("does not flag eval('2+2'), constant vm scripts, timers with functions, or file templates", () => {
    expect(inFile('routes/ssti/safe.js')).toEqual([]);
  });
});

describe('overall', () => {
  it('produces exactly the expected findings for the fixture project (no false positives)', () => {
    expect(
      findings
        .filter((f) => INJECTION.test(f.detectorId))
        .map((f) => `${f.detectorId} ${f.filePath}:${f.lineStart}`)
        .sort(),
    ).toEqual([
      'A1-sql-injection routes/sqli/login.ts:9',
      'A1-sql-injection routes/sqli/raw-concat.js:8',
      'A1-sql-injection routes/sqli/search.ts:9',
      'A1-sql-injection routes/sqli/unproven.js:5',
      'A2-nosql-injection routes/nosql/showProductReviews.ts:8',
      'A2-nosql-injection routes/nosql/updateProductReviews.ts:7',
      'A2-nosql-injection routes/nosql/whole-body.js:6',
      'A3-ssti routes/ssti/greeting.js:3',
      'A3-ssti routes/ssti/userProfile.ts:14',
      'A3-ssti routes/ssti/userProfile.ts:18',
    ]);
  });
});
