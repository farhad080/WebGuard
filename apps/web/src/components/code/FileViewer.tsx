import type { Finding } from '@webguard/core';
import { lazy, Suspense, useEffect, useId, useMemo, useRef } from 'react';
import { Link } from 'react-router-dom';
import { findingTitle, formatBytes, formatLocation } from '../../lib/findings';
import { SeverityBadge } from '../Badges';
import { Loading } from '../States';
import { BinaryFile, FileUnavailable, TruncatedNotice } from './FileStatus';
import { useScanFile, type FileMark } from './scan-file';

const MonacoCodeView = lazy(() => import('./MonacoCodeView'));

const LANGUAGE_LABEL: Record<string, string> = {
  javascript: 'JavaScript',
  typescript: 'TypeScript',
  csharp: 'C#',
  php: 'PHP',
  html: 'HTML',
  css: 'CSS',
  json: 'JSON',
  yaml: 'YAML',
  toml: 'TOML',
  xml: 'XML',
  sql: 'SQL',
};
const languageLabel = (l: string | null) =>
  l ? (LANGUAGE_LABEL[l] ?? l.charAt(0).toUpperCase() + l.slice(1)) : 'Plain text';

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea, [tabindex]:not([tabindex="-1"])';

/**
 * Modal full-file viewer for a finding's location: the file from the scan's extracted copy
 * (GET /api/scans/:id/file, the same fetch as the finding detail view), scrolled to and
 * highlighting the finding's lines, with every other finding in the file marked in the gutter
 * and listed in the side panel (selecting one moves the highlight to it). Opened from a file
 * (e.g. the Project Overview tree) with no finding selected, it just marks every finding.
 */
export function FileViewer({
  scanId,
  path,
  finding = null,
  fileFindings,
  onSelect,
  onClose,
}: {
  scanId: string;
  path: string;
  /** The finding to highlight and scroll to, if any. */
  finding?: Finding | null;
  /** All findings of the scan in this file (including `finding`). */
  fileFindings: readonly Finding[];
  onSelect: (findingId: string) => void;
  onClose: () => void;
}) {
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const file = useScanFile(scanId, path);

  const sorted = useMemo(
    () => [...fileFindings].sort((a, b) => a.lineStart - b.lineStart || a.lineEnd - b.lineEnd),
    [fileFindings],
  );
  const marks = useMemo<FileMark[]>(
    () =>
      sorted
        .filter((f) => f.id !== finding?.id)
        .map((f) => ({
          id: f.id,
          lineStart: f.lineStart,
          lineEnd: f.lineEnd,
          severity: f.severity,
          label: findingTitle(f),
        })),
    [sorted, finding?.id],
  );

  // Focus the dialog on open, give focus back to the opener on close, lock page scroll.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const { overflow } = document.body.style;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = overflow;
      opener?.focus?.();
    };
  }, []);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      onClose();
      return;
    }
    if (e.key !== 'Tab' || !dialogRef.current) return;
    // Keep Tab inside the dialog (Monaco's own textarea is part of the cycle).
    const items = [...dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
    const first = items[0];
    const last = items[items.length - 1];
    if (!first || !last) return;
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return (
    <div
      className="viewer-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className="file-viewer"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onKeyDown={onKeyDown}
      >
        <header className="file-viewer-head">
          <div className="file-viewer-title">
            <h2 id={titleId} className="mono">
              {path}
            </h2>
            <p className="muted small" data-testid="file-meta">
              {file.data && !file.isError ? (
                <>
                  {languageLabel(file.data.language)} · {formatBytes(file.data.size)}
                  {!file.data.binary && ` · ${file.data.lineCount.toLocaleString()} lines`}
                  {file.data.truncated && ' (truncated)'}
                </>
              ) : (
                ' '
              )}
            </p>
          </div>
          <button
            ref={closeRef}
            type="button"
            className="btn btn-small btn-secondary"
            onClick={onClose}
            aria-label="Close file viewer"
          >
            Close <span aria-hidden="true">✕</span>
          </button>
          <div className="file-viewer-summary" data-testid="viewer-summary">
            {finding ? (
              <>
                <SeverityBadge severity={finding.severity} />
                <span className="file-viewer-summary-text">
                  <strong>{findingTitle(finding)}</strong>{' '}
                  <span className="muted">
                    ·{' '}
                    {finding.lineEnd > finding.lineStart
                      ? `lines ${finding.lineStart}–${finding.lineEnd}`
                      : `line ${finding.lineStart}`}
                  </span>
                </span>
                <Link to={`/findings/${finding.id}`} className="small">
                  Finding details →
                </Link>
              </>
            ) : (
              <span className="file-viewer-summary-text muted">
                {sorted.length === 0
                  ? 'No findings in this file.'
                  : `${sorted.length} ${sorted.length === 1 ? 'finding' : 'findings'} marked in this file — select one to highlight it.`}
              </span>
            )}
          </div>
        </header>

        <div className="file-viewer-body">
          <nav className="file-viewer-list" aria-label={`Findings in ${path}`}>
            <p className="small muted">
              {sorted.length} {sorted.length === 1 ? 'finding' : 'findings'} in this file
            </p>
            <ul>
              {sorted.map((f) => (
                <li key={f.id}>
                  <button
                    type="button"
                    className={`file-viewer-item${f.id === finding?.id ? ' is-active' : ''}`}
                    aria-current={f.id === finding?.id ? 'true' : undefined}
                    onClick={() => onSelect(f.id)}
                  >
                    <span className={`swatch sev-${f.severity}`} aria-hidden="true" />
                    <span className="mono small">
                      L{f.lineStart}
                      {f.lineEnd > f.lineStart ? `–${f.lineEnd}` : ''}
                    </span>
                    <span className="file-viewer-item-title">{findingTitle(f)}</span>
                  </button>
                </li>
              ))}
            </ul>
          </nav>

          <div className="file-viewer-code">
            {file.isPending ? (
              <Loading label={`Loading ${path}…`} />
            ) : file.isError ? (
              <FileUnavailable error={file.error} path={path} />
            ) : file.data.binary ? (
              <BinaryFile file={file.data} />
            ) : (
              <>
                <TruncatedNotice file={file.data} range={finding ?? undefined} />
                <div className="file-viewer-editor">
                  <Suspense fallback={<Loading label="Loading editor…" />}>
                    <MonacoCodeView
                      path={path}
                      code={file.data.content}
                      lineStart={finding?.lineStart}
                      lineEnd={finding?.lineEnd}
                      marks={marks}
                      ariaLabel={
                        finding
                          ? `Source of ${formatLocation(finding)}, the finding's lines highlighted, ${marks.length} other ${marks.length === 1 ? 'finding' : 'findings'} marked`
                          : `Source of ${path}, ${marks.length} ${marks.length === 1 ? 'finding' : 'findings'} marked`
                      }
                    />
                  </Suspense>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
