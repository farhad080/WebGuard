import { createHash } from 'node:crypto';
import type { Finding } from '@webguard/core';

/** Whitespace-insensitive form of a code snippet (indentation/reflow don't change identity). */
export function normalizeCode(snippet: string): string {
  return snippet.replace(/\s+/g, ' ').trim();
}

/**
 * Stable identity of a finding across scans: detector + file + normalized code. Line numbers
 * are only used when there is no code to compare, so a finding whose code merely moved (lines
 * added above it) is still the same finding.
 */
export function findingFingerprint(
  f: Pick<Finding, 'detectorId' | 'filePath' | 'snippet' | 'lineStart' | 'lineEnd'>,
): string {
  const code = normalizeCode(f.snippet);
  const anchor = code ? `code:${code}` : `line:${f.lineStart}-${f.lineEnd}`;
  return createHash('sha256')
    .update(`${f.detectorId}\u0000${f.filePath}\u0000${anchor}`)
    .digest('hex');
}

export interface FindingDiff {
  fixed: Finding[];
  new: Finding[];
  persisting: { finding: Finding; previous: Finding }[];
}

/**
 * Diffs `current` against `baseline`. Fingerprints are matched as a multiset: two identical
 * findings in one file pair up one-to-one (closest line first), so a third copy appearing is
 * reported as new.
 */
export function diffFindings(baseline: Finding[], current: Finding[]): FindingDiff {
  const pool = new Map<string, Finding[]>();
  for (const f of baseline) {
    const key = findingFingerprint(f);
    pool.set(key, [...(pool.get(key) ?? []), f]);
  }
  const persisting: FindingDiff['persisting'] = [];
  const added: Finding[] = [];
  for (const f of [...current].sort((a, b) => a.lineStart - b.lineStart)) {
    const candidates = pool.get(findingFingerprint(f));
    if (!candidates?.length) {
      added.push(f);
      continue;
    }
    let best = 0;
    for (let i = 1; i < candidates.length; i++) {
      if (
        Math.abs(candidates[i]!.lineStart - f.lineStart) <
        Math.abs(candidates[best]!.lineStart - f.lineStart)
      ) {
        best = i;
      }
    }
    const [previous] = candidates.splice(best, 1);
    persisting.push({ finding: f, previous: previous! });
  }
  const fixed = [...pool.values()].flat();
  return { fixed, new: added, persisting };
}
