import type {
  Artifact as ArtifactRow,
  Finding as FindingRow,
  Project as ProjectRow,
  Scan as ScanRow,
} from '@prisma/client';
import type {
  Artifact,
  Finding,
  OwaspCategory,
  Project,
  Remediation,
  Scan,
  ScanSummary,
} from '@webguard/core';

// These map DB rows to the shared @webguard/core API contract. Assigning Prisma enum
// values to the core unions makes the compiler flag any drift between the two.

export function toProject(row: ProjectRow): Project {
  return {
    id: row.id,
    userId: row.userId,
    name: row.name,
    createdAt: row.createdAt.toISOString(),
  };
}

export function toScan(row: ScanRow): Scan {
  return {
    id: row.id,
    projectId: row.projectId,
    status: row.status,
    startedAt: row.startedAt?.toISOString() ?? null,
    finishedAt: row.finishedAt?.toISOString() ?? null,
    summary: (row.summaryJson as ScanSummary | null) ?? null,
    createdAt: row.createdAt.toISOString(),
  };
}

export function toFinding(row: FindingRow): Finding {
  return {
    id: row.id,
    scanId: row.scanId,
    detectorId: row.detectorId,
    owaspCategory: row.owaspCategory as OwaspCategory,
    severity: row.severity,
    confidence: row.confidence,
    filePath: row.filePath,
    lineStart: row.lineStart,
    lineEnd: row.lineEnd,
    snippet: row.snippet,
    explanation: row.explanation,
    fixSuggestion: row.fixSuggestion,
    contributingDetectors:
      row.contributingDetectors.length > 0 ? row.contributingDetectors : [row.detectorId],
    evidence: row.evidence,
    cwe: row.cwe,
    remediation: (row.remediationJson as Remediation | null) ?? null,
    createdAt: row.createdAt.toISOString(),
  };
}

export function toArtifact(row: ArtifactRow): Artifact {
  return {
    id: row.id,
    scanId: row.scanId,
    kind: row.kind,
    storageKey: row.storageKey,
    createdAt: row.createdAt.toISOString(),
  };
}
