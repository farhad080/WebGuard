import { Router } from 'express';
import { authMiddleware } from '../auth/middleware.js';
import { prisma } from '../db.js';
import { asyncHandler } from '../middleware/async-handler.js';
import { parseId } from './ownership.js';
import { toFinding } from './serializers.js';

export const findingsRouter = Router();
findingsRouter.use(authMiddleware);

/** One finding with its full remediation. Owned through scan → project → user; others get 404. */
findingsRouter.get(
  '/:id',
  asyncHandler(async (req, res) => {
    const id = parseId(req.params.id);
    const finding = id
      ? await prisma.finding.findFirst({
          where: { id, scan: { project: { userId: req.user!.id } } },
        })
      : null;
    if (!finding) {
      res.status(404).json({ error: 'Not found' });
      return;
    }
    res.json(toFinding(finding));
  }),
);
