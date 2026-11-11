import { Queue, Worker } from 'bullmq';
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

export async function closeScanQueue(): Promise<void> {
  await queue?.close();
  queue = undefined;
}

export function createScanWorker(concurrency = 2): Worker<ScanJobData> {
  return new Worker<ScanJobData>(
    config.scanQueueName,
    async (job) => {
      await processScan(job.data.scanId);
    },
    {
      connection: { ...redisConnection(), maxRetriesPerRequest: null },
      concurrency,
    },
  );
}
