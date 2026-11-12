import { useQuery } from '@tanstack/react-query';
import { lazy, Suspense } from 'react';
import { api } from '../../api/endpoints';
import { ErrorState, Loading } from '../States';

const MonacoCodeView = lazy(() => import('./MonacoCodeView'));

/** Fetches the (secret-redacted) file from the API and shows it in Monaco. */
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
  const source = useQuery({
    queryKey: ['source', scanId, path],
    queryFn: () => api.getSource(scanId, path),
    staleTime: Infinity,
    retry: false,
  });

  return (
    <div className="code-view">
      <div className="code-view-head mono">
        {path}{' '}
        <span className="muted">
          · lines {lineStart}–{lineEnd}
        </span>
      </div>
      {source.isPending ? (
        <Loading label="Loading source…" />
      ) : source.isError ? (
        <>
          <ErrorState
            title="Full file unavailable — showing the stored snippet"
            error={source.error}
          />
          <pre className="snippet">
            <code>{fallbackSnippet}</code>
          </pre>
        </>
      ) : (
        <div className="code-view-editor">
          <Suspense fallback={<Loading label="Loading editor…" />}>
            <MonacoCodeView
              path={path}
              code={source.data}
              lineStart={lineStart}
              lineEnd={lineEnd}
            />
          </Suspense>
        </div>
      )}
    </div>
  );
}
