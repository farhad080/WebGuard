import { useQuery } from '@tanstack/react-query';
import type { ScanFileMissingReason, Severity } from '@webguard/core';
import { api } from '../../api/endpoints';
import { ApiError } from '../../api/client';

/**
 * The one fetch of a scan file (GET /api/scans/:id/file), shared by the findings file viewer
 * and the finding detail code view, so both read the same cached, secret-redacted content.
 */
export function useScanFile(scanId: string, path: string, enabled = true) {
  return useQuery({
    queryKey: ['scan-file', scanId, path],
    queryFn: () => api.getFile(scanId, path),
    enabled,
    staleTime: Infinity,
    retry: false,
  });
}

/** The explained 404 of the file endpoint, or null for any other error. */
export function missingReason(
  error: unknown,
): { reason: ScanFileMissingReason; ignoredDir?: string } | null {
  if (!(error instanceof ApiError) || error.status !== 404) return null;
  const reason = error.body?.reason;
  if (
    reason !== 'ignored_dir' &&
    reason !== 'extracted_unavailable' &&
    reason !== 'not_ready' &&
    reason !== 'not_found'
  ) {
    return null;
  }
  const ignoredDir = error.body?.ignoredDir;
  return { reason, ...(typeof ignoredDir === 'string' ? { ignoredDir } : {}) };
}

export interface LineRange {
  lineStart: number;
  lineEnd: number;
}

/** Another finding in the same file, marked in the gutter. */
export interface FileMark extends LineRange {
  id: string;
  severity: Severity;
  label: string;
}

/** Clamps a range to lines 1..lineCount; null when it lies entirely past the end (truncated). */
export function clampRange(range: LineRange, lineCount: number): LineRange | null {
  const start = Math.max(1, range.lineStart);
  if (lineCount < 1 || start > lineCount) return null;
  return { lineStart: start, lineEnd: Math.min(Math.max(start, range.lineEnd), lineCount) };
}

/**
 * What each line of the viewer shows: 'active' for the selected finding's lines (highlighted),
 * 'other' for lines of the file's other findings (marked). Active wins where they overlap.
 */
export function lineRoles(
  active: Partial<LineRange>,
  others: readonly LineRange[],
  lineCount: number,
): Map<number, 'active' | 'other'> {
  const roles = new Map<number, 'active' | 'other'>();
  for (const o of others) {
    const r = clampRange(o, lineCount);
    if (r) for (let l = r.lineStart; l <= r.lineEnd; l++) roles.set(l, 'other');
  }
  const a =
    active.lineStart === undefined
      ? null
      : clampRange(
          { lineStart: active.lineStart, lineEnd: active.lineEnd ?? active.lineStart },
          lineCount,
        );
  if (a) for (let l = a.lineStart; l <= a.lineEnd; l++) roles.set(l, 'active');
  return roles;
}
