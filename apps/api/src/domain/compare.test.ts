import type { Finding } from '@webguard/core';
import { describe, expect, it } from 'vitest';
import { diffFindings, findingFingerprint } from './compare.js';

let n = 0;
function f(overrides: Partial<Finding>): Finding {
  n += 1;
  return {
    id: `f${n}`,
    scanId: 's',
    detectorId: 'A1-sql-injection',
    owaspCategory: 'A05:2025-Injection',
    severity: 'critical',
    confidence: 0.9,
    filePath: 'src/db.js',
    lineStart: 10,
    lineEnd: 10,
    snippet: "db.query('SELECT * FROM t WHERE id=' + id)",
    explanation: '',
    fixSuggestion: '',
    contributingDetectors: [],
    evidence: [],
    cwe: null,
    remediation: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

describe('findingFingerprint', () => {
  it('ignores line moves and whitespace, but not detector, file, or code', () => {
    const base = f({});
    expect(findingFingerprint(f({ lineStart: 42, lineEnd: 42 }))).toBe(findingFingerprint(base));
    expect(
      findingFingerprint(f({ snippet: "  db.query('SELECT * FROM t WHERE id='\n   + id)" })),
    ).toBe(findingFingerprint(base));
    expect(findingFingerprint(f({ detectorId: 'A2-nosql-injection' }))).not.toBe(
      findingFingerprint(base),
    );
    expect(findingFingerprint(f({ filePath: 'src/other.js' }))).not.toBe(findingFingerprint(base));
    expect(findingFingerprint(f({ snippet: "db.query('SELECT 1')" }))).not.toBe(
      findingFingerprint(base),
    );
  });

  it('falls back to the line range when there is no code', () => {
    expect(findingFingerprint(f({ snippet: '' }))).not.toBe(
      findingFingerprint(f({ snippet: '', lineStart: 11, lineEnd: 11 })),
    );
  });
});

describe('diffFindings', () => {
  it('classifies fixed, new, and persisting findings', () => {
    const keep = f({ lineStart: 10 });
    const gone = f({ detectorId: 'A4-xss', snippet: 'el.innerHTML = q' });
    const moved = f({ lineStart: 14, lineEnd: 14 });
    const added = f({ detectorId: 'A6-weak-crypto', snippet: "createHash('md5')" });

    const diff = diffFindings([keep, gone], [moved, added]);
    expect(diff.fixed.map((x) => x.id)).toEqual([gone.id]);
    expect(diff.new.map((x) => x.id)).toEqual([added.id]);
    expect(diff.persisting).toEqual([{ finding: moved, previous: keep }]);
  });

  it('matches duplicates one-to-one, so an extra copy is new', () => {
    const a1 = f({ lineStart: 5 });
    const a2 = f({ lineStart: 20 });
    const b1 = f({ lineStart: 6 });
    const b2 = f({ lineStart: 21 });
    const b3 = f({ lineStart: 40 });
    const diff = diffFindings([a1, a2], [b3, b1, b2]);
    expect(diff.persisting.map((p) => [p.finding.id, p.previous.id])).toEqual([
      [b1.id, a1.id],
      [b2.id, a2.id],
    ]);
    expect(diff.new.map((x) => x.id)).toEqual([b3.id]);
    expect(diff.fixed).toEqual([]);
  });

  it('handles empty sides', () => {
    const x = f({});
    expect(diffFindings([], [x]).new).toEqual([x]);
    expect(diffFindings([x], []).fixed).toEqual([x]);
  });
});
