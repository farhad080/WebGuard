import type { Prisma } from '@prisma/client';
import { Router } from 'express';
import { authMiddleware } from '../auth/middleware.js';
import { prisma } from '../db.js';
import { asyncHandler } from '../middleware/async-handler.js';
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
