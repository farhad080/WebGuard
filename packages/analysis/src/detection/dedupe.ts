import { combineConfidence, compareSeverity, maxSeverity, severityRank } from './scoring.js';
import type { FindingDraft, ValidatedFinding } from './types.js';

/** Strongest first: severity, then confidence, then id (for determinism). */
function byStrength(a: ValidatedFinding, b: ValidatedFinding): number {
  return (
    severityRank(b.severity) - severityRank(a.severity) ||
    b.confidence - a.confidence ||
    a.detectorId.localeCompare(b.detectorId)
  );
}

function unique(values: Iterable<string>): string[] {
  return [...new Set([...values].filter((v) => v.length > 0))];
}

/**
 * Turns raw engine output into the final finding list, in two passes:
 *
 * 1. **De-duplicate:** findings with the same (detectorId, filePath, lineStart) collapse into
 *    one, keeping the strongest and merging evidence.
 * 2. **Correlate:** findings from *different* detectors on the same (filePath, lineStart),
 *    OWASP category, and weakness (CWE, when detectors declare one) merge into one result. It keeps the highest severity, combines confidence
 *    (independent agreement → higher confidence), and lists every contributing detector.
 *    Different categories on the same line (e.g. a hardcoded secret and an injection) stay
 *    separate: they are distinct problems with distinct fixes.
 *
 * Output is sorted by severity, then file, then line.
 */
export function dedupeFindings(findings: readonly ValidatedFinding[]): FindingDraft[] {
  // Pass 1: same detector, same place.
  const perDetector = new Map<string, { best: ValidatedFinding; evidence: string[] }>();
  for (const f of findings) {
    const key = `${f.detectorId}\u0000${f.filePath}\u0000${f.lineStart}`;
    const existing = perDetector.get(key);
    if (!existing) {
      perDetector.set(key, { best: f, evidence: [f.evidence] });
    } else {
      existing.evidence.push(f.evidence);
      if (byStrength(f, existing.best) < 0) existing.best = f;
    }
  }

  // Pass 2: different detectors, same place and category.
  const groups = new Map<string, Array<{ best: ValidatedFinding; evidence: string[] }>>();
  for (const entry of perDetector.values()) {
    const f = entry.best;
    const key = `${f.filePath}\u0000${f.lineStart}\u0000${f.owaspCategory}\u0000${f.cwe ?? ''}`;
    const group = groups.get(key);
    if (group) group.push(entry);
    else groups.set(key, [entry]);
  }

  const drafts: FindingDraft[] = [];
  for (const group of groups.values()) {
    group.sort((a, b) => byStrength(a.best, b.best));
    const primary = group[0]!.best;
    drafts.push({
      detectorId: primary.detectorId,
      owaspCategory: primary.owaspCategory,
      severity: maxSeverity(group.map((g) => g.best.severity)),
      confidence:
        group.length === 1
          ? primary.confidence
          : combineConfidence(group.map((g) => g.best.confidence)),
      filePath: primary.filePath,
      lineStart: primary.lineStart,
      lineEnd: primary.lineEnd,
      snippet: primary.snippet,
      explanation: primary.explanation,
      fixSuggestion: primary.fixSuggestion,
      contributingDetectors: group.map((g) => g.best.detectorId),
      evidence: unique(group.flatMap((g) => g.evidence)),
    });
  }

  return drafts.sort(
    (a, b) =>
      compareSeverity(a.severity, b.severity) ||
      a.filePath.localeCompare(b.filePath) ||
      a.lineStart - b.lineStart ||
      a.detectorId.localeCompare(b.detectorId),
  );
}
