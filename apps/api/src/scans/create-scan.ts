import type { Scan } from '@prisma/client';
import { prisma } from '../db.js';
import { enqueueScan } from './queue.js';
import { getStorage, storageKeys } from './storage.js';

/**
 * Stores an uploaded ZIP for a project and queues its scan. Shared by the upload route and the
 * demo seed. If storing or queueing fails, the scan is marked failed (never left queued).
 */
export async function createQueuedScan(projectId: string, zipPath: string): Promise<Scan> {
  const scan = await prisma.scan.create({ data: { projectId } });
  try {
    const key = storageKeys.rawZip(scan.id);
    await getStorage().putFile(key, zipPath);
    await prisma.artifact.create({ data: { scanId: scan.id, kind: 'raw_zip', storageKey: key } });
    await enqueueScan(scan.id);
  } catch (err) {
    await prisma.scan.update({
      where: { id: scan.id },
      data: {
        status: 'failed',
        finishedAt: new Date(),
        summaryJson: { error: 'Failed to queue scan' },
      },
    });
    throw err;
  }
  return scan;
}
