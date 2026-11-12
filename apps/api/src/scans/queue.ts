import { Queue, QueueEvents, Worker, type Job } from 'bullmq';
import { findChromium } from '../reports/render-pdf.js';
import { generatePdfReport } from '../reports/report-service.js';
import { config } from '../config.js';
import { processScan } from './process-scan.js';

export interface ScanJobData {
  scanId: string;
}

export function redisConnection(url = config.redisUrl) {
  const parsed = new URL(url);
  return {
    host: parsed.hostname,
    port: Number(parsed.port || 6379),
    username: parsed.username ? decodeURIComponent(parsed.username) : undefined,
    password: parsed.password ? decodeURIComponent(parsed.password) : undefined,
    db: parsed.pathname.length > 1 ? Number(parsed.pathname.slice(1)) : 0,
    tls: parsed.protocol === 'rediss:' ? {} : undefined,
  };
}

let queue: Queue<ScanJobData> | undefined;

/** Lazily created so importing the app (e.g. in tests) doesn't open a Redis connection. */
export function getScanQueue(): Queue<ScanJobData> {
  queue ??= new Queue<ScanJobData>(config.scanQueueName, { connection: redisConnection() });
  return queue;
}

export async function enqueueScan(scanId: string): Promise<void> {
  await getScanQueue().add(
    'scan',
    { scanId },
    {
      jobId: scanId, // idempotent: one job per scan
      attempts: 1, // a failed scan stays failed; the user re-uploads
      removeOnComplete: { count: 1000 },
      removeOnFail: { count: 5000 },
    },
  );
}

let queueEvents: QueueEvents | undefined;
function getQueueEvents(): QueueEvents {
  queueEvents ??= new QueueEvents(config.scanQueueName, { connection: redisConnection() });
  return queueEvents;
}

const pdfJobId = (scanId: string) => `report-pdf-${scanId}`;

/** Queues PDF rendering for a scan (idempotent per scan; a finished/failed job is replaced). */
export async function enqueueReportPdf(scanId: string): Promise<Job<ScanJobData>> {
  const q = getScanQueue();
  const existing = await q.getJob(pdfJobId(scanId));
  if (existing && ((await existing.isCompleted()) || (await existing.isFailed()))) {
    await existing.remove().catch(() => undefined);
  }
  return q.add(
    'report-pdf',
    { scanId },
    {
      jobId: pdfJobId(scanId),
      attempts: 1,
      removeOnComplete: { count: 1000 },
      removeOnFail: { count: 1000 },
    },
  );
}

export type PdfWaitResult =
  { status: 'done' } | { status: 'failed'; message: string } | { status: 'timeout' };

/** Queue the PDF job and wait (bounded) for a worker to finish it. */
export async function requestReportPdf(
  scanId: string,
  timeoutMs = config.reportPdfWaitMs,
): Promise<PdfWaitResult> {
  const events = getQueueEvents();
  await events.waitUntilReady();
  const job = await enqueueReportPdf(scanId);
  try {
    await job.waitUntilFinished(events, timeoutMs);
    return { status: 'done' };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/timed out|timeout/i.test(message)) return { status: 'timeout' };
    return { status: 'failed', message };
  }
}

export async function closeScanQueue(): Promise<void> {
  await queueEvents?.close();
  queueEvents = undefined;
  await queue?.close();
  queue = undefined;
}

/** One worker process handles both scans and report PDFs (job names "scan" / "report-pdf"). */
export function createScanWorker(concurrency = 2): Worker<ScanJobData> {
  return new Worker<ScanJobData>(
    config.scanQueueName,
    async (job) => {
      if (job.name === 'report-pdf') {
        await generatePdfReport(job.data.scanId);
        return;
      }
      await processScan(job.data.scanId);
      // Pre-render the PDF so the first download is instant (off the request thread).
      if (config.reportPdfOnComplete && findChromium()) {
        await enqueueReportPdf(job.data.scanId).catch(() => undefined);
      }
    },
    {
      connection: { ...redisConnection(), maxRetriesPerRequest: null },
      concurrency,
    },
  );
}
