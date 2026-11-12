import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { Prisma } from '@prisma/client';
import {
  countFindings,
  createDefaultDetectorRegistry,
  createDetectionContext,
  dedupeFindings,
  DetectionEngine,
  parseSourceFiles,
  INFORMATIONAL_NOTES,
  ProfilerService,
  RemediationService,
  type DetectorRegistry,
  type ParsedFile,
} from '@webguard/analysis';
import type { ParseErrorSample, ScanSummary } from '@webguard/core';
import { config } from '../config.js';
import { AnthropicRemediationProvider } from '../remediation/anthropic-provider.js';
import { prisma } from '../db.js';
import { ExtractionError, ExtractorService, type ExtractionLimits } from './extractor.js';
import { getStorage, storageKeys, uploadDirectory, type StorageService } from './storage.js';

export interface ProcessScanOptions {
  storage?: StorageService;
  limits?: Partial<ExtractionLimits>;
  /** Detectors to run (default: every built-in detector). */
  detectors?: DetectorRegistry;
  /** Remediation engine (default: deterministic templates, LLM assist per config). */
  remediation?: RemediationService;
}

const MAX_PARSE_ERROR_SAMPLES = 20;

let sharedRemediation: RemediationService | undefined;
/** Built once: LLM assist only when REMEDIATION_LLM=true and an API key is configured. */
function defaultRemediation(): RemediationService {
  if (!sharedRemediation) {
    const llm = config.remediationLlm;
    sharedRemediation = new RemediationService({
      llm: {
        enabled: llm.enabled,
        provider:
          llm.enabled && llm.apiKey
            ? new AnthropicRemediationProvider(llm.apiKey, llm.model)
            : undefined,
      },
    });
  }
  return sharedRemediation;
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

    // Analysis inputs: profile the project, then parse every supported source file.
    // A file that fails to parse is recorded and skipped; it never fails the scan.
    const profile = await new ProfilerService({
      maxFileBytes: config.analysisMaxFileBytes,
    }).profile(extractDir);
    const files: ParsedFile[] = [];
    let parseErrors = 0;
    const parseErrorSamples: ParseErrorSample[] = [];
    for await (const file of parseSourceFiles(extractDir, profile)) {
      files.push(file);
      if (file.parseError) {
        parseErrors++;
        if (parseErrorSamples.length < MAX_PARSE_ERROR_SAMPLES) {
          const { message, line, column } = file.parseError;
          parseErrorSamples.push({ path: file.path, message, line, column });
        }
      }
    }

    // Detection: run every registered detector stage by stage, then de-duplicate/correlate.
    // A failing detector is recorded in detectorErrors; it never fails the scan.
    const ctx = createDetectionContext({ rootDir: extractDir, profile, files });
    const engine = new DetectionEngine(options.detectors ?? createDefaultDetectorRegistry());
    const detection = await engine.run(ctx);
    // Remediation: attach why/impact, steps, a (contextualized) secure example and references
    // to every finding before it is persisted.
    const findings = await (options.remediation ?? defaultRemediation()).enrichFindings(
      dedupeFindings(detection.findings),
      ctx,
    );
    const counts = countFindings(findings);

    const summary: ScanSummary = {
      filesExtracted: result.filesExtracted,
      totalBytes: result.totalBytes,
      skippedEntries: result.skippedEntries,
      profile,
      filesParsed: files.filter((f) => f.ast).length,
      parseErrors,
      parseErrorSamples,
      detectors: detection.executed,
      findingsTotal: counts.total,
      findingsBySeverity: counts.bySeverity,
      findingsByOwaspCategory: counts.byOwaspCategory,
      detectorErrors: detection.detectorErrors.map(({ detectorId, message }) => ({
        detectorId,
        message,
      })),
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
        await tx.scan.updateMany({
          where: { id: scanId },
          data: {
            status: 'completed',
            finishedAt: new Date(),
            summaryJson: summary as unknown as Prisma.InputJsonObject,
          },
        });
      },
      { timeout: 60_000 },
    );
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
