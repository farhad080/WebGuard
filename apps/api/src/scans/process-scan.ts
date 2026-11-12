import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { Prisma } from '@prisma/client';
import {
  countFindings,
  INFORMATIONAL_NOTES,
  type DetectorRegistry,
  type RemediationService,
} from '@webguard/analysis';
import type { ScanSummary } from '@webguard/core';
import { config } from '../config.js';
import { computeRollup } from '../reports/rollup.js';
import { prisma } from '../db.js';
import {
  analyzeProject,
  buildDetectorRegistry,
  buildRemediation,
  ScanLimitError,
  type AnalysisOutput,
} from './analyze.js';
import { ExtractionError, ExtractorService, type ExtractionLimits } from './extractor.js';
import { runAnalysisInThread } from './sandbox.js';
import {
  getStorage,
  RM_RETRY,
  storageKeys,
  uploadDirectory,
  type StorageService,
} from './storage.js';

export interface ProcessScanOptions {
  storage?: StorageService;
  limits?: Partial<ExtractionLimits>;
  /**
   * Detectors to run. Supplying detectors or a remediation service runs the analysis
   * in-process (with the same cooperative time/memory budget) instead of in the isolated
   * analysis thread, since live objects can't cross a thread boundary.
   */
  detectors?: DetectorRegistry;
  remediation?: RemediationService;
  /** Wall-clock budget for the whole job (default SCAN_TIMEOUT_MS). */
  timeoutMs?: number;
  /** Heap cap for the analysis thread (default SCAN_MAX_HEAP_MB). */
  maxHeapMb?: number;
}

/** Rejects with a ScanLimitError if `work` is still pending at `deadline`. */
async function withDeadline<T>(work: Promise<T>, deadline: number, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          new ScanLimitError(
            `Scan exceeded the ${Math.round(timeoutMs / 1000)} s time limit and was stopped`,
          ),
        ),
      Math.max(0, deadline - Date.now()),
    );
  });
  try {
    return await Promise.race([work, expired]);
  } finally {
    clearTimeout(timer);
  }
}

const FINDINGS_BATCH_SIZE = 1000;

/**
 * Drives one scan through queued → running → completed | failed:
 * download → safe-extract → profile → parse → detect → de-dup → persist findings + summary.
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

  const timeoutMs = options.timeoutMs ?? config.scanTimeoutMs;
  const maxHeapMb = options.maxHeapMb ?? config.scanMaxHeapMb;
  const deadline = Date.now() + timeoutMs;
  const tempDir = await mkdtemp(path.join(os.tmpdir(), `webguard-scan-${scanId}-`));
  try {
    const raw = await prisma.artifact.findFirst({ where: { scanId, kind: 'raw_zip' } });
    if (!raw) throw new ExtractionError('No uploaded archive found for this scan');

    const zipPath = path.join(tempDir, 'upload.zip');
    const extractDir = path.join(tempDir, 'src');
    await storage.downloadToFile(raw.storageKey, zipPath);

    const result = await withDeadline(extractor.extract(zipPath, extractDir), deadline, timeoutMs);

    const extractedKey = storageKeys.extracted(scanId);
    await uploadDirectory(storage, extractDir, extractedKey);
    await prisma.artifact.create({
      data: { scanId, kind: 'extracted', storageKey: extractedKey },
    });

    // Analysis (profile → parse → detect → remediate) only reads the extracted files.
    const network = { osv: config.osvAdvisories };
    let analysis: AnalysisOutput;
    if (options.detectors || options.remediation) {
      const maxHeapBytes = maxHeapMb * 1024 * 1024;
      analysis = await withDeadline(
        analyzeProject(extractDir, {
          maxFileBytes: config.analysisMaxFileBytes,
          ignoredDirs: config.ignoredDirs,
          detectors: options.detectors ?? buildDetectorRegistry(network),
          remediation: options.remediation ?? (await buildRemediation(config.remediationLlm)),
          budget: { deadline, timeoutMs, maxHeapBytes },
        }),
        deadline,
        timeoutMs,
      );
    } else {
      analysis = await runAnalysisInThread(
        {
          extractDir,
          maxFileBytes: config.analysisMaxFileBytes,
          ignoredDirs: config.ignoredDirs,
          network,
          llm: config.remediationLlm,
        },
        { timeoutMs: Math.max(1, deadline - Date.now()), maxHeapMb },
      );
    }
    const { findings, profile } = analysis;
    const counts = countFindings(findings);

    const summary: ScanSummary = {
      filesExtracted: result.filesExtracted,
      totalBytes: result.totalBytes,
      skippedEntries: result.skippedEntries,
      extractedFiles: result.filesExtracted,
      skippedDirs: result.skippedDirs,
      skippedFileCount: result.skippedFileCount,
      profile,
      filesParsed: analysis.filesParsed,
      parseErrors: analysis.parseErrors,
      parseErrorSamples: analysis.parseErrorSamples,
      detectors: analysis.detectors,
      findingsTotal: counts.total,
      findingsBySeverity: counts.bySeverity,
      findingsByOwaspCategory: counts.byOwaspCategory,
      detectorErrors: analysis.detectorErrors,
      // Documented weakness classes that need manual/dynamic review: shown, not dropped.
      informationalNotes: [...INFORMATIONAL_NOTES],
    };

    // Findings and the completed status land atomically, so the summary counts always match
    // the persisted rows (and a retried scan can't leave duplicates behind).
    await prisma.$transaction(
      async (tx) => {
        await tx.finding.deleteMany({ where: { scanId } });
        for (let i = 0; i < findings.length; i += FINDINGS_BATCH_SIZE) {
          await tx.finding.createMany({
            data: findings.slice(i, i + FINDINGS_BATCH_SIZE).map(({ remediation, ...f }) => ({
              scanId,
              ...f,
              remediationJson: remediation as unknown as Prisma.InputJsonObject,
            })),
          });
        }
        // Authoritative rollup + risk grade, computed from the rows just persisted, so the
        // dashboard and every report read the same numbers.
        const persisted = await tx.finding.findMany({
          where: { scanId },
          select: { severity: true, owaspCategory: true, confidence: true },
        });
        const rollup = computeRollup(persisted);
        const finalSummary: ScanSummary = {
          ...summary,
          rollup,
          findingsTotal: rollup.total,
          findingsBySeverity: rollup.bySeverity,
          findingsByOwaspCategory: rollup.byOwaspCategory,
        };
        await tx.scan.updateMany({
          where: { id: scanId },
          data: {
            status: 'completed',
            finishedAt: new Date(),
            summaryJson: finalSummary as unknown as Prisma.InputJsonObject,
          },
        });
      },
      { timeout: 60_000 },
    );
  } catch (err) {
    // Archive problems and exceeded limits are reported verbatim; anything else gets a generic
    // message so internal details (paths, stack traces) never reach the client.
    const expected = err instanceof ExtractionError || err instanceof ScanLimitError;
    const message = expected ? (err as Error).message : 'Internal error while processing the scan';
    if (!expected) console.error(`[worker] scan ${scanId} failed:`, err);

    await storage.deletePrefix(storageKeys.extracted(scanId)).catch(() => undefined);
    await prisma.artifact
      .deleteMany({ where: { scanId, kind: 'extracted' } })
      .catch(() => undefined);
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
    // The temp dir (raw ZIP copy + extracted tree) never outlives the job, and the stored
    // upload is no longer needed once the scan has an outcome: the extracted tree (kept for
    // the code view of a completed scan) and the reports are what remain.
    await rm(tempDir, { recursive: true, force: true, ...RM_RETRY }).catch((err) =>
      console.error(`[worker] could not remove temp dir of scan ${scanId}`, err),
    );
    await discardRawUpload(scanId, storage);
  }
}

async function discardRawUpload(scanId: string, storage: StorageService): Promise<void> {
  try {
    await storage.delete(storageKeys.rawZip(scanId));
    await prisma.artifact.deleteMany({ where: { scanId, kind: 'raw_zip' } });
  } catch (err) {
    console.error(`[worker] could not remove the upload of scan ${scanId}`, err);
  }
}
