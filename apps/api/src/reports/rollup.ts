import type { OwaspCategory, RiskGrade, ScanRollup, Severity } from '@webguard/core';

/**
 * Risk model (documented in the README):
 *
 *   weightedRisk = Σ severityWeight(finding.severity) × finding.confidence
 *   riskScore    = round(100 × (1 − e^(−weightedRisk / SATURATION)))
 *
 * The exponential saturates: the first serious findings move the score most, and 100 is only
 * approached, never exceeded. Grades by score: A < 10 ≤ B < 25 ≤ C < 50 ≤ D < 75 ≤ F.
 * Override: any critical finding with confidence ≥ 0.8 caps the grade at D (never better),
 * so a single proven critical issue can't hide behind an otherwise clean project.
 */
export const RISK_MODEL = {
  severityWeights: { critical: 10, high: 5, medium: 2, low: 0.5, info: 0 } satisfies Record<
    Severity,
    number
  >,
  saturation: 25,
  gradeThresholds: [
    { grade: 'A', below: 10 },
    { grade: 'B', below: 25 },
    { grade: 'C', below: 50 },
    { grade: 'D', below: 75 },
  ] as Array<{ grade: RiskGrade; below: number }>,
  criticalCap: { minConfidence: 0.8, worstAllowedBest: 'D' as RiskGrade },
} as const;

export interface RollupRow {
  severity: Severity;
  owaspCategory: string;
  confidence: number;
}

const ORDER: RiskGrade[] = ['A', 'B', 'C', 'D', 'F'];

export function computeRollup(rows: readonly RollupRow[], now = new Date()): ScanRollup {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byOwaspCategory: Partial<Record<OwaspCategory, number>> = {};
  let weightedRisk = 0;
  let provenCriticals = 0;
  for (const r of rows) {
    bySeverity[r.severity]++;
    const cat = r.owaspCategory as OwaspCategory;
    byOwaspCategory[cat] = (byOwaspCategory[cat] ?? 0) + 1;
    weightedRisk += RISK_MODEL.severityWeights[r.severity] * r.confidence;
    if (r.severity === 'critical' && r.confidence >= RISK_MODEL.criticalCap.minConfidence)
      provenCriticals++;
  }
  weightedRisk = Math.round(weightedRisk * 100) / 100;
  const riskScore = Math.round(100 * (1 - Math.exp(-weightedRisk / RISK_MODEL.saturation)));
  let grade: RiskGrade = RISK_MODEL.gradeThresholds.find((t) => riskScore < t.below)?.grade ?? 'F';
  let gradeReason = `risk score ${riskScore}/100 from weighted risk ${weightedRisk}`;
  const cap = RISK_MODEL.criticalCap.worstAllowedBest;
  if (provenCriticals > 0 && ORDER.indexOf(grade) < ORDER.indexOf(cap)) {
    grade = cap;
    gradeReason = `capped at ${cap}: ${provenCriticals} high-confidence critical finding${provenCriticals > 1 ? 's' : ''} (score alone would be better)`;
  }
  return {
    total: rows.length,
    bySeverity,
    byOwaspCategory,
    riskScore,
    grade,
    weightedRisk,
    gradeReason,
    computedAt: now.toISOString(),
  };
}
