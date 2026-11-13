import { lazy, Suspense } from 'react';
import { Loading } from '../States';
import { BinaryFile, FileUnavailable, TruncatedNotice } from './FileStatus';
import { useScanFile } from './scan-file';

const MonacoCodeView = lazy(() => import('./MonacoCodeView'));

/** Finding detail code view: the file (shared fetch, secret-redacted) in Monaco. */
export function CodeView({
  scanId,
  path,
  lineStart,
  lineEnd,
  fallbackSnippet,
}: {
  scanId: string;
  path: string;
  lineStart: number;
  lineEnd: number;
  fallbackSnippet: string;
}) {
  const file = useScanFile(scanId, path);
  const snippet = (
    <pre className="snippet">
      <code>{fallbackSnippet}</code>
    </pre>
  );

  return (
    <div className="code-view">
      <div className="code-view-head mono">
        {path}{' '}
        <span className="muted">
          · lines {lineStart}–{lineEnd}
        </span>
      </div>
      {file.isPending ? (
        <Loading label="Loading source…" />
      ) : file.isError ? (
        <>
          <FileUnavailable error={file.error} path={path} />
          <p className="muted small code-view-fallback">Stored snippet:</p>
          {snippet}
        </>
      ) : file.data.binary ? (
        <BinaryFile file={file.data} />
      ) : (
        <>
          <TruncatedNotice file={file.data} range={{ lineStart, lineEnd }} />
          <div className="code-view-editor">
            <Suspense fallback={<Loading label="Loading editor…" />}>
              <MonacoCodeView
                path={path}
                code={file.data.content}
                lineStart={lineStart}
                lineEnd={lineEnd}
              />
            </Suspense>
          </div>
        </>
      )}
    </div>
  );
}
