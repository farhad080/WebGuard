import type { Prisma, Scan } from '@prisma/client';
import type { Finding, ScanComparison, ScanRef, ScanSummary, Severity } from '@webguard/core';
import { Router } from 'express';
import { authMiddleware } from '../auth/middleware.js';
import { prisma } from '../db.js';
import { asyncHandler } from '../middleware/async-handler.js';
import { diffFindings } from './compare.js';
import { findOwnedScan, parseId } from './ownership.js';
import { readScanFile } from './scan-file.js';
import { findingsQuerySchema } from './schemas.js';
import { toFinding, toScan } from './serializers.js';

export const scansRouter = Router();
scansRouter.use(authMiddleware);

const notFound = { error: 'Not found' } as const;

scansRouter.get(
  '/:id',
  asyncHandler(async (req, res) => {
    const id = parseId(req.params.id);
    const scan = id && (await findOwnedScan(req.user!.id, id));
    if (!scan) {
      res.status(404).json(notFound);
      return;
    }
    res.json(toScan(scan));
  }),
);

scansRouter.get(
  '/:id/findings',
  asyncHandler(async (req, res) => {
    const id = parseId(req.params.id);
    const scan = id && (await findOwnedScan(req.user!.id, id));
    if (!scan) {
      res.status(404).json(notFound);
      return;
    }

    const parsed = findingsQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid query', details: parsed.error.flatten().fieldErrors });
      return;
    }
    const { severity, owaspCategory, minConfidence } = parsed.data;

    const where: Prisma.FindingWhereInput = { scanId: scan.id };
    if (severity) where.severity = { in: severity };
    if (owaspCategory) where.owaspCategory = owaspCategory;
    if (minConfidence !== undefined) where.confidence = { gte: minConfidence };

    const findings = await prisma.finding.findMany({
      where,
      orderBy: [{ filePath: 'asc' }, { lineStart: 'asc' }, { id: 'asc' }],
    });
    res.json(findings.map(toFinding));
  }),
);

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};
const bySeverity = (a: Finding, b: Finding) =>
  SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
  a.filePath.localeCompare(b.filePath) ||
  a.lineStart - b.lineStart;

const toScanRef = (scan: Scan): ScanRef => ({
  id: scan.id,
  createdAt: scan.createdAt.toISOString(),
  finishedAt: scan.finishedAt?.toISOString() ?? null,
  rollup: (scan.summaryJson as ScanSummary | null)?.rollup ?? null,
});

/**
 * Diff of two completed scans of the same project: findings fixed since `against`, new ones,
 * and the ones still open (matched by fingerprint, see compare.ts).
 */
scansRouter.get(
  '/:id/compare',
  asyncHandler(async (req, res) => {
    const id = parseId(req.params.id);
    const againstId = parseId(typeof req.query.against === 'string' ? req.query.against : '');
    const scan = id && (await findOwnedScan(req.user!.id, id));
    if (!scan) {
      res.status(404).json(notFound);
      return;
    }
    if (!againstId) {
      res.status(400).json({ error: 'Query parameter "against" must be a scan id' });
      return;
    }
    const against = await findOwnedScan(req.user!.id, againstId);
    if (!against) {
      res.status(404).json(notFound);
      return;
    }
    if (against.projectId !== scan.projectId) {
      res.status(400).json({ error: 'Both scans must belong to the same project' });
      return;
    }
    if (scan.status !== 'completed' || against.status !== 'completed') {
      res.status(409).json({ error: 'Both scans must be completed to compare them' });
      return;
    }

    const [current, baseline] = await Promise.all(
      [scan.id, against.id].map(async (scanId) =>
        (await prisma.finding.findMany({ where: { scanId } })).map(toFinding),
      ),
    );
    const diff = diffFindings(baseline!, current!);
    const scanRef = toScanRef(scan);
    const againstRef = toScanRef(against);
    const body: ScanComparison = {
      scan: scanRef,
      against: againstRef,
      fixed: diff.fixed.sort(bySeverity),
      new: diff.new.sort(bySeverity),
      persisting: diff.persisting.sort((a, b) => bySeverity(a.finding, b.finding)),
      summary: {
        fixed: diff.fixed.length,
        new: diff.new.length,
        persisting: diff.persisting.length,
        totalDelta: current!.length - baseline!.length,
        riskScoreDelta:
          scanRef.rollup && againstRef.rollup
            ? scanRef.rollup.riskScore - againstRef.rollup.riskScore
            : null,
      },
    };
    res.json(body);
  }),
);

/**
 * One file of the scan's extracted copy (JSON: path, language, size, lineCount, content,
 * truncated, binary). Ownership-checked, path-confined to this scan's extracted directory,
 * size-capped (MAX_VIEW_FILE_KB) and secret-redacted: see scan-file.ts. The single source for
 * the findings file viewer and the finding detail code view.
 */
scansRouter.get(
  '/:id/file',
  asyncHandler(async (req, res) => {
    const id = parseId(req.params.id);
    const scan = id && (await findOwnedScan(req.user!.id, id));
    if (!scan) {
      res.status(404).json(notFound);
      return;
    }
    res.setHeader('Cache-Control', 'private, no-store');
    const result = await readScanFile(scan, req.query.path);
    if (!result.ok) {
      const { status, error } = result;
      res.status(status).json(
        status === 404
          ? {
              error,
              reason: result.reason,
              ...(result.ignoredDir ? { ignoredDir: result.ignoredDir } : {}),
            }
          : { error },
      );
      return;
    }
    res.json(result.file);
  }),
);
