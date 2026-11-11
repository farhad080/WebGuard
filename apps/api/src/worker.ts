import { prisma } from './db.js';
import { createScanWorker } from './scans/queue.js';

const worker = createScanWorker();

worker.on('ready', () => console.log('[worker] waiting for scan jobs'));
worker.on('completed', (job) => console.log(`[worker] scan ${job.data.scanId} completed`));
worker.on('failed', (job, err) =>
  console.log(`[worker] scan ${job?.data.scanId ?? '?'} failed: ${err.message}`),
);
worker.on('error', (err) => console.error('[worker] error', err));

async function shutdown(signal: string): Promise<void> {
  console.log(`[worker] ${signal} received, finishing active jobs...`);
  await worker.close();
  await prisma.$disconnect();
  process.exit(0);
}

process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));
