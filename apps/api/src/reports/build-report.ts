import type { Project, Scan } from '@prisma/client';
import { INFORMATIONAL_NOTES } from '@webguard/analysis';
import type { ScanReport, ScanSummary } from '@webguard/core';
import { prisma } from '../db.js';
import { toFinding } from '../domain/serializers.js';
import { computeRollup } from './rollup.js';

/** Assembles the full ScanReport for a (completed) scan from the database. */
export async function buildScanReport(scan: Scan, project: Project): Promise<ScanReport> {
  // `severity` is a Postgres enum declared critical → info, so ascending = most severe first.
  const rows = await prisma.finding.findMany({
    where: { scanId: scan.id },
    orderBy: [{ severity: 'asc' }, { filePath: 'asc' }, { lineStart: 'asc' }, { id: 'asc' }],
  });
  const summary = (scan.summaryJson ?? {}) as ScanSummary;
  const profile = summary.profile;

  return {
    reportVersion: 1,
    generatedAt: new Date().toISOString(),
    project: { id: project.id, name: project.name },
    scan: {
      id: scan.id,
      status: scan.status,
      createdAt: scan.createdAt.toISOString(),
      startedAt: scan.startedAt?.toISOString() ?? null,
      finishedAt: scan.finishedAt?.toISOString() ?? null,
    },
    profile: profile
      ? {
          languages: profile.languages,
          frameworks: profile.frameworks,
          sourceFiles: profile.sourceFiles.length,
          filesParsed: summary.filesParsed ?? 0,
          parseErrors: summary.parseErrors ?? 0,
          skippedFileCount: summary.skippedFileCount ?? 0,
          skippedDirs: summary.skippedDirs ?? [],
        }
      : null,
    // The stored rollup is authoritative; older scans get one computed on the fly.
    rollup: summary.rollup ?? computeRollup(rows),
    findings: rows.map(toFinding),
    informationalNotes: summary.informationalNotes ?? [...INFORMATIONAL_NOTES],
    detectors: summary.detectors ?? [],
    detectorErrors: summary.detectorErrors ?? [],
  };
}
