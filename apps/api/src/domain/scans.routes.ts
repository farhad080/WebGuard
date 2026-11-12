import type { Prisma, Scan } from '@prisma/client';
import type { Finding, ScanComparison, ScanRef, ScanSummary, Severity } from '@webguard/core';
import { Router } from 'express';
import { authMiddleware } from '../auth/middleware.js';
import { prisma } from '../db.js';
import { asyncHandler } from '../middleware/async-handler.js';
import { getStorage, storageKeys } from '../scans/storage.js';
import { diffFindings } from './compare.js';
import { findOwnedScan, parseId } from './ownership.js';
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

const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const SECRETS_DETECTOR = 'A5-hardcoded-secrets';

/**
 * Raw text of one extracted project file, for the finding code view. Ownership-checked;
 * only `/`-separated relative paths are accepted (storage keys reject traversal too).
 * Lines flagged by the secrets detector are replaced with their redacted snippet so the code
 * view never re-exposes a secret the findings redact.
 */
scansRouter.get(
  '/:id/source',
  asyncHandler(async (req, res) => {
    const id = parseId(req.params.id);
    const scan = id && (await findOwnedScan(req.user!.id, id));
    if (!scan) {
      res.status(404).json(notFound);
      return;
    }
    const filePath = typeof req.query.path === 'string' ? req.query.path : '';
    const segments = filePath.split('/');
    if (
      !filePath ||
      filePath.length > 1024 ||
      filePath.includes('\\') ||
      filePath.includes('\0') ||
      filePath.startsWith('/') ||
      segments.some((s) => s === '' || s === '.' || s === '..')
    ) {
      res.status(400).json({ error: 'Invalid path' });
      return;
    }
    const key = `${storageKeys.extracted(scan.id)}/${filePath}`;
    const storage = getStorage();
    if (!(await storage.exists(key))) {
      res.status(404).json(notFound);
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    try {
      const stream = await storage.getStream(key);
      for await (const chunk of stream) {
        size += (chunk as Buffer).length;
        if (size > MAX_SOURCE_BYTES) {
          stream.destroy();
          res.status(413).json({ error: 'File is too large to display' });
          return;
        }
        chunks.push(chunk as Buffer);
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'EISDIR' || code === 'ENOENT') {
        res.status(404).json(notFound);
        return;
      }
      throw err;
    }
    const buffer = Buffer.concat(chunks);
    if (buffer.includes(0)) {
      res.status(415).json({ error: 'Binary file' });
      return;
    }
    const lines = buffer.toString('utf8').split('\n');
    const secrets = await prisma.finding.findMany({
      where: {
        scanId: scan.id,
        filePath,
        OR: [
          { detectorId: SECRETS_DETECTOR },
          { contributingDetectors: { has: SECRETS_DETECTOR } },
        ],
      },
      select: { lineStart: true, lineEnd: true, snippet: true },
    });
    for (const s of secrets) {
      const redacted = s.snippet.split('\n');
      for (let line = s.lineStart; line <= s.lineEnd && line <= lines.length; line++) {
        lines[line - 1] = redacted[line - s.lineStart] ?? '[redacted]';
      }
    }
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.send(lines.join('\n'));
  }),
);
