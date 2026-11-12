import type { Prisma } from '@prisma/client';
import { Router } from 'express';
import { authMiddleware } from '../auth/middleware.js';
import { prisma } from '../db.js';
import { asyncHandler } from '../middleware/async-handler.js';
import { getStorage, storageKeys } from '../scans/storage.js';
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
