import { createWriteStream } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { Transform, type Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { ignoredDirOf } from '@webguard/analysis';
import yauzl, { type Entry, type ZipFile } from 'yauzl';

/**
 * Safe ZIP extraction. Uploaded archives are fully attacker-controlled, so every entry is
 * validated before anything touches the filesystem:
 *  - zip-slip: entry paths are resolved and must stay inside the destination directory
 *  - zip bombs: entry count, total uncompressed bytes (declared AND actually written), and
 *    per-entry compression ratio are capped
 *  - symlinks, devices, FIFOs, and encrypted entries are skipped, never materialized
 *  - entries under an ignored directory (node_modules, dist, .git, …: `ignoredDirs`) are
 *    skipped BEFORE any cap is applied: never written, never counted toward the file-count,
 *    size, or ratio caps. Their paths are still validated, so a zip-slip name fails the scan
 *    even when it sits under node_modules/.
 */

export interface ExtractionLimits {
  /** Max total uncompressed bytes across all entries. */
  maxTotalBytes: number;
  /** Max number of entries in the archive (files + directories). */
  maxFiles: number;
  /** Max uncompressed/compressed ratio for a single entry. */
  maxCompressionRatio: number;
  /** Only entries at least this large are subject to the ratio check (small text compresses well). */
  ratioCheckMinBytes: number;
  /** Directory names (any path segment) whose contents are not extracted. Default: none. */
  ignoredDirs?: readonly string[];
}

/** At most this many skipped directories are listed in the result (the file count is exact). */
export const MAX_LISTED_SKIPPED_DIRS = 100;

export interface ExtractionResult {
  filesExtracted: number;
  totalBytes: number;
  /** Symlinks, special files, and encrypted entries (outside ignored dirs) not extracted. */
  skippedEntries: number;
  /** Top-most ignored directories that had entries, sorted (at most MAX_LISTED_SKIPPED_DIRS). */
  skippedDirs: string[];
  /** File entries under ignored directories (not extracted, not counted against any cap). */
  skippedFileCount: number;
}

/** A failure caused by the archive itself. Its message is safe to show to the user. */
export class ExtractionError extends Error {
  override name = 'ExtractionError';
}

const S_IFMT = 0o170000;
const S_IFREG = 0o100000;
const S_IFDIR = 0o040000;
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i;

function describe(name: string): string {
  return JSON.stringify(name.length > 200 ? `${name.slice(0, 200)}…` : name);
}

/**
 * Returns the absolute path an entry would be written to, or throws if the name is unsafe:
 * absolute paths, drive letters, `..` segments, backslashes, control characters, `:` (Windows
 * drive/alternate data streams), reserved device names, or anything resolving outside `destDir`.
 */
export function resolveSafeEntryPath(destDir: string, entryName: string): string {
  const unsafe = (reason: string) =>
    new ExtractionError(`Unsafe path in archive (${reason}): ${describe(entryName)}`);

  if (entryName.length === 0 || entryName.length > 1024) throw unsafe('invalid length');
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f]/.test(entryName)) throw unsafe('control characters');
  if (entryName.includes('\\')) throw unsafe('backslash');
  if (entryName.startsWith('/') || /^[a-zA-Z]:/.test(entryName)) throw unsafe('absolute path');
  if (entryName.includes(':')) throw unsafe('colon');

  const segments = entryName.split('/').filter((s) => s !== '' && s !== '.');
  for (const segment of segments) {
    if (segment === '..') throw unsafe('path traversal');
    // Windows strips trailing dots/spaces, so "..." or ". ." could alias "." / "..".
    if (/^[. ]+$/.test(segment)) throw unsafe('dot segment');
    if (WINDOWS_RESERVED.test(segment)) throw unsafe('reserved name');
  }
  if (segments.length === 0) throw unsafe('empty path');

  const root = path.resolve(destDir);
  const target = path.resolve(root, ...segments);
  const rel = path.relative(root, target);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw unsafe('escapes destination');
  }
  return target;
}

function openZip(zipPath: string): Promise<ZipFile> {
  return new Promise((resolve, reject) => {
    yauzl.open(
      zipPath,
      { lazyEntries: true, autoClose: false, validateEntrySizes: true, decodeStrings: true },
      (err, zip) =>
        err || !zip ? reject(err ?? new Error('Failed to open archive')) : resolve(zip),
    );
  });
}

function openEntryStream(zip: ZipFile, entry: Entry): Promise<Readable> {
  return new Promise((resolve, reject) => {
    zip.openReadStream(entry, (err, stream) =>
      err || !stream ? reject(err ?? new Error('Failed to read entry')) : resolve(stream),
    );
  });
}

/** Reads the next central-directory entry, or null at the end. */
function nextEntry(zip: ZipFile): Promise<Entry | null> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      zip.off('entry', onEntry);
      zip.off('end', onEnd);
      zip.off('error', onError);
    };
    const onEntry = (entry: Entry) => {
      cleanup();
      resolve(entry);
    };
    const onEnd = () => {
      cleanup();
      resolve(null);
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    zip.on('entry', onEntry);
    zip.on('end', onEnd);
    zip.on('error', onError);
    zip.readEntry();
  });
}

/** Normalizes yauzl's own validation/corruption errors into user-facing ExtractionErrors. */
function toExtractionError(err: unknown): unknown {
  if (err instanceof ExtractionError) return err;
  if (!(err instanceof Error)) return err;
  // Filesystem errors (ENOSPC, EACCES, ...) are infrastructure problems, not archive problems.
  const code = (err as NodeJS.ErrnoException).code;
  if (code === 'EEXIST') return new ExtractionError('Archive contains duplicate entries');
  if (typeof code === 'string') return err;
  if (/invalid relative path|absolute path|invalid characters in fileName/i.test(err.message)) {
    return new ExtractionError(`Unsafe path in archive: ${err.message}`);
  }
  return new ExtractionError(`Invalid or corrupt ZIP archive: ${err.message}`);
}

/** 2147483648 → "2048 MB"; small test caps stay in bytes. */
function formatBytes(bytes: number): string {
  const mb = bytes / (1024 * 1024);
  return mb >= 1 ? `${Math.round(mb * 10) / 10} MB` : `${bytes} bytes`;
}

export class ExtractorService {
  constructor(private readonly limits: ExtractionLimits) {}

  /** Extracts `zipPath` into `destDir` (created if missing). Throws ExtractionError on unsafe input. */
  async extract(zipPath: string, destDir: string): Promise<ExtractionResult> {
    const { maxTotalBytes, maxFiles, maxCompressionRatio, ratioCheckMinBytes } = this.limits;
    const ignored = new Set(this.limits.ignoredDirs ?? []);
    await mkdir(destDir, { recursive: true });

    let zip: ZipFile;
    try {
      zip = await openZip(zipPath);
    } catch (err) {
      throw toExtractionError(err);
    }

    const result: ExtractionResult = {
      filesExtracted: 0,
      totalBytes: 0,
      skippedEntries: 0,
      skippedDirs: [],
      skippedFileCount: 0,
    };
    const skippedDirs = new Set<string>();
    let declaredTotal = 0;
    // Entries outside ignored dirs (files + directories): what MAX_EXTRACTED_FILES caps. The
    // archive's own entry count can't be used up front, since it includes ignored entries.
    let counted = 0;

    try {
      for (let entry = await nextEntry(zip); entry; entry = await nextEntry(zip)) {
        // Validate the path of every entry, including ones we end up skipping.
        const target = resolveSafeEntryPath(destDir, entry.fileName);

        const madeByUnix = entry.versionMadeBy >> 8 === 3;
        const mode = madeByUnix ? (entry.externalFileAttributes >>> 16) & S_IFMT : 0;
        const isDirectory = entry.fileName.endsWith('/') || mode === S_IFDIR;

        // Dependency/build/VCS trees: skipped before any counting or cap.
        if (ignored.size > 0) {
          const name =
            isDirectory && !entry.fileName.endsWith('/') ? `${entry.fileName}/` : entry.fileName;
          const dir = ignoredDirOf(name, ignored);
          if (dir !== null) {
            if (skippedDirs.size < MAX_LISTED_SKIPPED_DIRS) skippedDirs.add(dir);
            if (!isDirectory) result.skippedFileCount++;
            continue;
          }
        }

        counted++;
        if (counted > maxFiles) {
          throw new ExtractionError(
            `Archive has too many entries (more than ${maxFiles} outside ignored directories; limit ${maxFiles}, MAX_EXTRACTED_FILES)`,
          );
        }
        if (isDirectory) continue;
        if (mode !== 0 && mode !== S_IFREG) {
          // Symlink, device, FIFO, socket: never materialize.
          result.skippedEntries++;
          continue;
        }
        if (entry.generalPurposeBitFlag & 0x1) {
          result.skippedEntries++; // encrypted
          continue;
        }

        declaredTotal += entry.uncompressedSize;
        if (declaredTotal > maxTotalBytes) {
          throw new ExtractionError(
            `Archive exceeds the maximum uncompressed size (${formatBytes(maxTotalBytes)}; MAX_EXTRACTED_MB)`,
          );
        }
        if (entry.uncompressedSize >= ratioCheckMinBytes) {
          const ratio =
            entry.compressedSize > 0 ? entry.uncompressedSize / entry.compressedSize : Infinity;
          if (ratio > maxCompressionRatio) {
            throw new ExtractionError(
              `Entry ${describe(entry.fileName)} exceeds the maximum compression ratio (${maxCompressionRatio}:1; MAX_COMPRESSION_RATIO)`,
            );
          }
        }

        await mkdir(path.dirname(target), { recursive: true });
        // Count real bytes too: never trust sizes declared in the archive headers.
        const counter = new Transform({
          transform(chunk: Buffer, _enc, callback) {
            result.totalBytes += chunk.length;
            if (result.totalBytes > maxTotalBytes) {
              callback(
                new ExtractionError(
                  `Archive exceeds the maximum uncompressed size (${formatBytes(maxTotalBytes)}; MAX_EXTRACTED_MB)`,
                ),
              );
              return;
            }
            callback(null, chunk);
          },
        });
        // 'wx' fails if the file already exists (duplicate or case-colliding entries).
        await pipeline(
          await openEntryStream(zip, entry),
          counter,
          createWriteStream(target, { flags: 'wx' }),
        );
        result.filesExtracted++;
      }
      result.skippedDirs = [...skippedDirs].sort();
      return result;
    } catch (err) {
      throw toExtractionError(err);
    } finally {
      zip.close();
    }
  }
}
