import os from 'node:os';
import path from 'node:path';
import type { Scan } from '@prisma/client';
import { BINARY_EXTENSIONS, detectLanguage, ignoredDirOf } from '@webguard/analysis';
import type { ScanFile, ScanFileMissingReason, ScanSummary } from '@webguard/core';
import { config } from '../config.js';
import { prisma } from '../db.js';
import { ExtractionError, resolveSafeEntryPath } from '../scans/extractor.js';
import { getStorage, InvalidStorageKeyError, storageKeys } from '../scans/storage.js';

/**
 * GET /api/scans/:id/file — one file of a scan's extracted copy, for the findings file viewer
 * and the finding detail (Monaco) view. The caller has already checked scan ownership.
 *
 * Confinement, in layers:
 *  1. the path must be a clean `/`-separated relative path: no absolute/drive paths, `..`, `.`
 *     or empty segments, backslashes, control characters, `:`, or reserved device names — the
 *     same rules the extractor's zip-slip guard applies to archive entries;
 *  2. it is only ever joined onto THIS scan's `scans/<id>/extracted` storage prefix, which the
 *     storage layer re-validates against its root;
 *  3. the file must be a regular file whose real path (symlinks resolved) is still inside the
 *     storage root; a symlink at the path itself is never followed.
 *
 * At most MAX_VIEW_FILE_KB is read; a larger file returns its head with `truncated: true`.
 * Binary files return `binary: true` and no content. Lines the secrets detector flagged are
 * replaced with their redacted snippet so the viewer never re-exposes a redacted secret.
 */

const SECRETS_DETECTOR = 'A5-hardcoded-secrets';
/** How much of the head is inspected for binary content. */
const BINARY_SNIFF_BYTES = 8000;
const VALIDATION_ROOT = path.join(os.tmpdir(), 'webguard-path-check');

export class InvalidViewPathError extends Error {
  override name = 'InvalidViewPathError';
}

/** Returns the normalized path, or throws InvalidViewPathError with a user-safe reason. */
export function validateViewPath(raw: unknown): string {
  if (typeof raw !== 'string' || raw === '') throw new InvalidViewPathError('Missing path');
  if (raw.length > 1024) throw new InvalidViewPathError('Path is too long');
  if (raw.startsWith('/') || /^[a-zA-Z]:/.test(raw)) {
    throw new InvalidViewPathError('Absolute paths are not allowed');
  }
  if (raw.split('/').some((s) => s === '' || s === '.' || s === '..')) {
    throw new InvalidViewPathError(
      'Path must be relative to the project, without . or .. segments',
    );
  }
  try {
    // The extractor's zip-slip guard: backslashes, control chars, `:`, reserved names, escape.
    resolveSafeEntryPath(VALIDATION_ROOT, raw);
  } catch (err) {
    if (err instanceof ExtractionError) {
      throw new InvalidViewPathError(err.message.replace(/^Unsafe path in archive/, 'Unsafe path'));
    }
    throw err;
  }
  return raw;
}

/** Text vs. binary: known binary extensions, NUL bytes, or mostly control characters. */
export function looksBinary(filePath: string, head: Buffer): boolean {
  const ext = path.posix.extname(filePath).toLowerCase();
  if (BINARY_EXTENSIONS.has(ext)) return true;
  const sample = head.subarray(0, BINARY_SNIFF_BYTES);
  if (sample.includes(0)) return true;
  let control = 0;
  for (const byte of sample) {
    // Control characters other than \t \n \r \f \v and ESC (ANSI colors in logs).
    if (byte < 0x20 && ![0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1b].includes(byte)) control++;
  }
  return sample.length > 0 && control / sample.length > 0.1;
}

/** The directory that explains why `filePath` was never extracted, if any. */
function ignoredDirFor(filePath: string, scan: Scan): string | null {
  const byConfig = ignoredDirOf(filePath, new Set(config.ignoredDirs));
  if (byConfig) return byConfig;
  // The scan's own record of what it skipped (the config may have changed since).
  const skipped = (scan.summaryJson as ScanSummary | null)?.skippedDirs ?? [];
  return skipped.find((dir) => filePath.startsWith(`${dir}/`)) ?? null;
}

export type ScanFileResult =
  | { ok: true; file: ScanFile }
  | { ok: false; status: 400; error: string }
  | { ok: false; status: 404; error: string; reason: ScanFileMissingReason; ignoredDir?: string };

const MESSAGES: Record<ScanFileMissingReason, string> = {
  ignored_dir:
    'This file was not scanned: it is in an ignored dependency/build directory, which is never extracted.',
  extracted_unavailable:
    "This scan's extracted files are no longer available (they were deleted, or the scan did not complete).",
  not_ready: 'This scan has not extracted its files yet. Try again when it has completed.',
  not_found: 'This file is not in the scan.',
};

const missing = (reason: ScanFileMissingReason, ignoredDir?: string): ScanFileResult => ({
  ok: false,
  status: 404,
  error: MESSAGES[reason],
  reason,
  ...(ignoredDir ? { ignoredDir } : {}),
});

export async function readScanFile(scan: Scan, rawPath: unknown): Promise<ScanFileResult> {
  let filePath: string;
  try {
    filePath = validateViewPath(rawPath);
  } catch (err) {
    if (err instanceof InvalidViewPathError) return { ok: false, status: 400, error: err.message };
    throw err;
  }

  if (scan.status === 'queued' || scan.status === 'running') return missing('not_ready');

  const maxBytes = config.maxViewFileBytes;
  const storage = getStorage();
  const extractedKey = storageKeys.extracted(scan.id);
  let head: { size: number; data: Buffer } | null;
  try {
    // One extra byte tells "exactly maxBytes" apart from "larger".
    head = await storage.readHead(`${extractedKey}/${filePath}`, maxBytes + 1);
  } catch (err) {
    if (err instanceof InvalidStorageKeyError) {
      return { ok: false, status: 400, error: 'Path resolves outside the scan' };
    }
    throw err;
  }

  if (!head) {
    const ignoredDir = ignoredDirFor(filePath, scan);
    if (ignoredDir) return missing('ignored_dir', ignoredDir);
    const artifact = await prisma.artifact.findFirst({
      where: { scanId: scan.id, kind: 'extracted' },
      select: { id: true },
    });
    if (!artifact || !(await storage.exists(extractedKey))) return missing('extracted_unavailable');
    return missing('not_found');
  }

  const language = detectLanguage(
    path.posix.basename(filePath),
    head.data.subarray(0, 512).toString('utf8'),
  );
  const base = { path: filePath, language, size: head.size, maxBytes };

  if (looksBinary(filePath, head.data)) {
    return {
      ok: true,
      file: { ...base, lineCount: 0, content: '', truncated: head.size > maxBytes, binary: true },
    };
  }

  const truncated = head.size > maxBytes;
  let data = head.data.subarray(0, maxBytes);
  if (truncated) {
    // End on a whole line so the last line shown is never a fragment (or half a UTF-8 char).
    const lastNewline = data.lastIndexOf(0x0a);
    if (lastNewline > 0) data = data.subarray(0, lastNewline + 1);
  }
  const lines = data.toString('utf8').split('\n');

  const secrets = await prisma.finding.findMany({
    where: {
      scanId: scan.id,
      filePath,
      OR: [{ detectorId: SECRETS_DETECTOR }, { contributingDetectors: { has: SECRETS_DETECTOR } }],
    },
    select: { lineStart: true, lineEnd: true, snippet: true },
  });
  for (const s of secrets) {
    const redacted = s.snippet.split('\n');
    for (let line = s.lineStart; line <= s.lineEnd && line <= lines.length; line++) {
      lines[line - 1] = redacted[line - s.lineStart] ?? '[redacted]';
    }
  }

  const content = lines.join('\n');
  // A trailing newline does not start another line.
  const lineCount = content === '' ? 0 : lines.length - (content.endsWith('\n') ? 1 : 0);
  return { ok: true, file: { ...base, lineCount, content, truncated, binary: false } };
}
