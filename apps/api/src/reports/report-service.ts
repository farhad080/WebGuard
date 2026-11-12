import { prisma } from '../db.js';
import { getStorage } from '../scans/storage.js';
import { buildScanReport } from './build-report.js';
import { renderReportHtml } from './render-html.js';
import { renderPdf } from './render-pdf.js';

export const reportKeys = {
  pdf: (scanId: string) => `scans/${scanId}/report.pdf`,
};

/** Existing PDF report for a scan, if its artifact row and stored file both exist. */
export async function findStoredPdf(scanId: string): Promise<string | undefined> {
  const artifact = await prisma.artifact.findFirst({
    where: { scanId, kind: 'report', storageKey: reportKeys.pdf(scanId) },
  });
  if (!artifact) return undefined;
  return (await getStorage().exists(artifact.storageKey)) ? artifact.storageKey : undefined;
}

/**
 * Renders the scan's report to PDF, stores it, and records a `report` artifact. Runs in the
 * worker (BullMQ job "report-pdf"), never on the request thread.
 */
export async function generatePdfReport(scanId: string): Promise<string> {
  const scan = await prisma.scan.findUniqueOrThrow({
    where: { id: scanId },
    include: { project: true },
  });
  if (scan.status !== 'completed')
    throw new Error(`scan ${scanId} is ${scan.status}, not completed`);
  const report = await buildScanReport(scan, scan.project);
  const pdf = await renderPdf(renderReportHtml(report));
  const key = reportKeys.pdf(scanId);
  await getStorage().put(key, pdf);
  await prisma.$transaction([
    prisma.artifact.deleteMany({ where: { scanId, kind: 'report', storageKey: key } }),
    prisma.artifact.create({ data: { scanId, kind: 'report', storageKey: key } }),
  ]);
  return key;
}
