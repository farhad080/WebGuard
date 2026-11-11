import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { ScanSummary } from '@webguard/core';
import { config } from '../config.js';
import { prisma } from '../db.js';
import { ExtractionError, ExtractorService, type ExtractionLimits } from './extractor.js';
import { getStorage, storageKeys, uploadDirectory, type StorageService } from './storage.js';

export interface ProcessScanOptions {
  storage?: StorageService;
  limits?: Partial<ExtractionLimits>;
}

/**
 * Drives one scan through queued → running → completed | failed.
 * Detection is a placeholder for now: the summary only reports extraction stats.
 */
export async function processScan(scanId: string, options: ProcessScanOptions = {}): Promise<void> {
  const storage = options.storage ?? getStorage();
  const extractor = new ExtractorService({ ...config.extraction, ...options.limits });

  // Atomic claim: only a queued scan can start, so a duplicate job is a no-op.
  const claimed = await prisma.scan.updateMany({
    where: { id: scanId, status: 'queued' },
    data: { status: 'running', startedAt: new Date() },
  });
  if (claimed.count === 0) return;

  const tempDir = await mkdtemp(path.join(os.tmpdir(), `webguard-scan-${scanId}-`));
  try {
    const raw = await prisma.artifact.findFirst({ where: { scanId, kind: 'raw_zip' } });
    if (!raw) throw new ExtractionError('No uploaded archive found for this scan');

    const zipPath = path.join(tempDir, 'upload.zip');
    const extractDir = path.join(tempDir, 'src');
    await storage.downloadToFile(raw.storageKey, zipPath);

    const result = await extractor.extract(zipPath, extractDir);

    const extractedKey = storageKeys.extracted(scanId);
    await uploadDirectory(storage, extractDir, extractedKey);
    await prisma.artifact.create({
      data: { scanId, kind: 'extracted', storageKey: extractedKey },
    });

    const summary: ScanSummary = {
      filesExtracted: result.filesExtracted,
      totalBytes: result.totalBytes,
      skippedEntries: result.skippedEntries,
      detectors: [],
    };
    await prisma.scan.updateMany({
      where: { id: scanId },
      data: { status: 'completed', finishedAt: new Date(), summaryJson: { ...summary } },
    });
  } catch (err) {
    // Archive problems are reported verbatim; anything else gets a generic message so
    // internal details (paths, stack traces) never reach the client.
    const message =
      err instanceof ExtractionError ? err.message : 'Internal error while processing the scan';
    if (!(err instanceof ExtractionError)) console.error(`[worker] scan ${scanId} failed:`, err);

    await storage.deletePrefix(storageKeys.extracted(scanId)).catch(() => undefined);
    await prisma.scan
      .updateMany({
        where: { id: scanId },
        data: { status: 'failed', finishedAt: new Date(), summaryJson: { error: message } },
      })
      .catch((updateErr) =>
        console.error(`[worker] could not mark scan ${scanId} failed`, updateErr),
      );
    throw err;
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}
