import type { Request, Response } from 'express';
import { Router } from 'express';
import { authMiddleware } from '../auth/middleware.js';
import { prisma } from '../db.js';
import { findOwnedScan, parseId } from '../domain/ownership.js';
import { asyncHandler } from '../middleware/async-handler.js';
import { requestReportPdf } from '../scans/queue.js';
import { getStorage } from '../scans/storage.js';
import { buildScanReport } from './build-report.js';
import { renderReportHtml } from './render-html.js';
import { findStoredPdf } from './report-service.js';

/** Report exports, mounted under /api/scans. Same ownership rule: other users' scans are 404. */
export const reportsRouter = Router();
reportsRouter.use(authMiddleware);

async function loadCompletedScan(req: Request, res: Response) {
  const id = parseId(req.params.id);
  const scan = id ? await findOwnedScan(req.user!.id, id) : null;
  if (!scan) {
    res.status(404).json({ error: 'Not found' });
    return undefined;
  }
  if (scan.status !== 'completed') {
    res
      .status(409)
      .json({ error: `Scan is ${scan.status}; reports are available once it completes` });
    return undefined;
  }
  const project = await prisma.project.findUniqueOrThrow({ where: { id: scan.projectId } });
  return { scan, project };
}

const fileName = (scanId: string, ext: string) => `webguard-report-${scanId}.${ext}`;

reportsRouter.get(
  '/:id/report.json',
  asyncHandler(async (req, res) => {
    const loaded = await loadCompletedScan(req, res);
    if (!loaded) return;
    res.setHeader('Content-Disposition', `inline; filename="${fileName(loaded.scan.id, 'json')}"`);
    res.json(await buildScanReport(loaded.scan, loaded.project));
  }),
);

reportsRouter.get(
  '/:id/report.html',
  asyncHandler(async (req, res) => {
    const loaded = await loadCompletedScan(req, res);
    if (!loaded) return;
    const html = renderReportHtml(await buildScanReport(loaded.scan, loaded.project));
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `inline; filename="${fileName(loaded.scan.id, 'html')}"`);
    // The report embeds untrusted code snippets (escaped): forbid every network load and script.
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
    );
    res.send(html);
  }),
);

reportsRouter.get(
  '/:id/report.pdf',
  asyncHandler(async (req, res) => {
    const loaded = await loadCompletedScan(req, res);
    if (!loaded) return;
    const scanId = loaded.scan.id;

    let key = await findStoredPdf(scanId);
    if (!key) {
      // Render in the worker (queue), never on the request thread; wait a bounded time.
      const result = await requestReportPdf(scanId);
      if (result.status === 'timeout') {
        res.setHeader('Retry-After', '10');
        res.status(202).json({ status: 'generating', retryAfterSeconds: 10 });
        return;
      }
      if (result.status === 'failed') {
        res.status(503).json({ error: 'PDF rendering failed', detail: result.message });
        return;
      }
      key = await findStoredPdf(scanId);
      if (!key) {
        res.status(503).json({ error: 'PDF rendering failed', detail: 'report was not stored' });
        return;
      }
    }
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName(scanId, 'pdf')}"`);
    (await getStorage().getStream(key)).pipe(res);
  }),
);
