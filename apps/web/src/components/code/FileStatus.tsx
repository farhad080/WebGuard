import type { ScanFile } from '@webguard/core';
import { formatBytes } from '../../lib/findings';
import { ErrorState } from '../States';
import { missingReason, type LineRange } from './scan-file';

/** Explains a failed file fetch: ignored directory, cleaned-up scan, not ready, or missing. */
export function FileUnavailable({ error, path }: { error: unknown; path: string }) {
  const missing = missingReason(error);
  if (!missing) return <ErrorState title="Could not load this file" error={error} />;
  const { reason, ignoredDir } = missing;
  const [title, body] =
    reason === 'ignored_dir'
      ? [
          'This file wasn’t scanned',
          <>
            It was in an ignored dependency/build directory
            {ignoredDir ? (
              <>
                {' '}
                (<code>{ignoredDir}/</code>)
              </>
            ) : null}
            , which is never extracted or analyzed.
          </>,
        ]
      : reason === 'extracted_unavailable'
        ? [
            'Source no longer available',
            'This scan’s extracted copy has been removed (or the scan did not complete), so the file can’t be shown. Re-scan the project to view its code.',
          ]
        : reason === 'not_ready'
          ? ['Not extracted yet', 'The scan is still running. Try again when it has completed.']
          : ['File not found', `${path} is not in this scan’s extracted copy.`];
  return (
    <div className="state state-empty" role="status" data-reason={reason}>
      <strong>{title}</strong>
      <span>{body}</span>
    </div>
  );
}

export function BinaryFile({ file }: { file: ScanFile }) {
  return (
    <div className="state state-empty" role="status">
      <strong>Binary file</strong>
      <span>
        {file.path} ({formatBytes(file.size)}) is not a text file, so it can’t be shown.
      </span>
    </div>
  );
}

/** Notice for a file cut at MAX_VIEW_FILE_KB, and whether the flagged lines were cut off. */
export function TruncatedNotice({ file, range }: { file: ScanFile; range?: LineRange }) {
  if (!file.truncated) return null;
  const cut = range !== undefined && range.lineStart > file.lineCount;
  return (
    <p className="notice small" role="note">
      Large file: showing the first {file.lineCount.toLocaleString()} lines (
      {formatBytes(file.maxBytes)} of {formatBytes(file.size)}).
      {cut && ' The flagged lines are beyond the part shown.'}
    </p>
  );
}
