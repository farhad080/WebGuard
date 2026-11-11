import type { OwaspCategory, Severity } from '@webguard/core';

/** The shared severity scale, most severe first. */
export const SEVERITIES = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
] as const satisfies readonly Severity[];

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && Object.hasOwn(SEVERITY_RANK, value);
}

export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity];
}

/** Sort comparator: most severe first. */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[b] - SEVERITY_RANK[a];
}

export function maxSeverity(severities: readonly Severity[]): Severity {
  return severities.reduce<Severity>(
    (max, s) => (SEVERITY_RANK[s] > SEVERITY_RANK[max] ? s : max),
    'info',
  );
}

export type ConfidenceBand = 'high' | 'medium' | 'low';

/** ≥ 0.8 high, ≥ 0.5 medium, otherwise low. */
export function confidenceBand(confidence: number): ConfidenceBand {
  if (confidence >= 0.8) return 'high';
  if (confidence >= 0.5) return 'medium';
  return 'low';
}

export function clampConfidence(confidence: number): number {
  return Math.min(1, Math.max(0, confidence));
}

/**
 * Combines confidences from independent detectors that agree (noisy-OR):
 * 1 − Π(1 − cᵢ). Two 0.6 signals → 0.84. Agreement raises confidence but never exceeds 1.
 */
export function combineConfidence(confidences: readonly number[]): number {
  const missProbability = confidences.reduce((p, c) => p * (1 - clampConfidence(c)), 1);
  return Math.round((1 - missProbability) * 1000) / 1000;
}

/** Keeps findings at or above a confidence threshold (for reports and UI filters). */
export function filterByConfidence<T extends { confidence: number }>(
  findings: readonly T[],
  minConfidence: number,
): T[] {
  return findings.filter((f) => f.confidence >= minConfidence);
}

export interface FindingCounts {
  total: number;
  bySeverity: Record<Severity, number>;
  byOwaspCategory: Partial<Record<OwaspCategory, number>>;
}

export function countFindings(
  findings: readonly { severity: Severity; owaspCategory: OwaspCategory }[],
): FindingCounts {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byOwaspCategory: Partial<Record<OwaspCategory, number>> = {};
  for (const f of findings) {
    bySeverity[f.severity]++;
    byOwaspCategory[f.owaspCategory] = (byOwaspCategory[f.owaspCategory] ?? 0) + 1;
  }
  return { total: findings.length, bySeverity, byOwaspCategory };
}
