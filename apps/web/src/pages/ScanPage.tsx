import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import type { Scan, ScanStatus } from '@webguard/core';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { api } from '../api/endpoints';
import { StatusBadge } from '../components/Badges';
import { Dashboard } from '../components/Dashboard';
import { FindingsTable } from '../components/FindingsTable';
import { InformationalNotes } from '../components/InformationalNotes';
import { ReportButtons } from '../components/ReportButtons';
import { ProjectOverview } from '../components/overview/ProjectOverview';
import { ErrorState, Loading } from '../components/States';
import { Tabs } from '../components/Tabs';
import { formatDateTime, formatDuration } from '../lib/findings';

/** Poll cadence for an in-flight scan (mutable so tests can shorten it). */
export const scanPolling = { intervalMs: 2000 };

const STEPS: { status: ScanStatus; label: string }[] = [
  { status: 'queued', label: 'Queued' },
  { status: 'running', label: 'Analyzing' },
  { status: 'completed', label: 'Done' },
];

function ScanProgress({ scan }: { scan: Scan }) {
  const failed = scan.status === 'failed';
  // Completed → every step done; failed → the last step shows the failure.
  const current =
    scan.status === 'completed'
      ? STEPS.length
      : failed
        ? 2
        : STEPS.findIndex((s) => s.status === scan.status);
  return (
    <ol className="stepper" aria-label="Scan progress">
      {STEPS.map((step, i) => {
        const state =
          i < current ? 'done' : i === current ? (failed ? 'failed' : 'current') : 'todo';
        const label = failed && i === 2 ? 'Failed' : step.label;
        return (
          <li
            key={step.status}
            className={`step step-${state}`}
            aria-current={state === 'current' ? 'step' : undefined}
          >
            <span className="step-dot" aria-hidden="true">
              {state === 'done' ? '✓' : state === 'failed' ? '✕' : i + 1}
            </span>
            {label}
          </li>
        );
      })}
    </ol>
  );
}

/** The latest completed scan of the same project that ran before this one. */
function usePreviousScan(scan: Scan | undefined) {
  const scans = useQuery({
    queryKey: ['scans', scan?.projectId],
    queryFn: () => api.listScans(scan!.projectId),
    enabled: scan?.status === 'completed',
  });
  if (!scan || !scans.data) return null;
  return (
    scans.data
      .filter(
        (s) =>
          s.id !== scan.id &&
          s.status === 'completed' &&
          s.summary?.rollup &&
          new Date(s.createdAt).getTime() < new Date(scan.createdAt).getTime(),
      )
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0] ?? null
  );
}

/** "node_modules, dist" — at most 4 names, then "+N more". */
function skippedDirsLabel(dirs: string[]): string {
  return dirs.length > 4
    ? `${dirs.slice(0, 4).join(', ')} +${dirs.length - 4} more`
    : dirs.join(', ');
}

export function ScanPage() {
  const { scanId = '' } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') === 'overview' ? 'overview' : 'dashboard';
  const scan = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => api.getScan(scanId),
    // Poll until the worker finishes; the page never blocks on the scan.
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return s === 'completed' || s === 'failed' ? false : scanPolling.intervalMs;
    },
  });
  const completed = scan.data?.status === 'completed';
  const finalStatus =
    scan.data?.status === 'completed' || scan.data?.status === 'failed' ? scan.data.status : null;
  const projectIdOfScan = scan.data?.projectId;
  const qc = useQueryClient();
  // Once the scan reaches a final state, lists cached while it was in flight are stale.
  useEffect(() => {
    if (!finalStatus || !projectIdOfScan) return;
    void qc.invalidateQueries({ queryKey: ['scans', projectIdOfScan] });
    void qc.invalidateQueries({ queryKey: ['projects'] });
  }, [finalStatus, projectIdOfScan, qc]);
  const findings = useQuery({
    queryKey: ['findings', scanId],
    queryFn: () => api.listFindings(scanId),
    enabled: completed,
  });
  const previous = usePreviousScan(scan.data);

  if (scan.isPending) return <Loading label="Loading scan…" />;
  if (scan.isError)
    return (
      <ErrorState title="Scan unavailable" error={scan.error} onRetry={() => scan.refetch()} />
    );

  const s = scan.data;
  const summary = s.summary ?? {};
  const rollup = summary.rollup;
  const profile = summary.profile;

  return (
    <div className="page">
      <nav aria-label="Breadcrumb" className="crumbs">
        <Link to="/projects">Projects</Link> <span aria-hidden="true">/</span>{' '}
        <Link to={`/projects/${s.projectId}`}>Project</Link> <span aria-hidden="true">/</span>{' '}
        <span aria-current="page">Scan</span>
      </nav>
      <div className="page-head">
        <h1>
          Scan <span className="muted small mono">{s.id.slice(0, 8)}</span>
        </h1>
        <StatusBadge status={s.status} />
      </div>
      <p className="muted small">
        Uploaded {formatDateTime(s.createdAt)}
        {formatDuration(s.startedAt, s.finishedAt) &&
          ` · took ${formatDuration(s.startedAt, s.finishedAt)}`}
      </p>

      <ScanProgress scan={s} />

      {(s.status === 'queued' || s.status === 'running') && (
        <div className="card live" role="status" aria-live="polite" data-testid="scan-live">
          <span className="spinner" aria-hidden="true" />
          <div>
            <strong>
              {s.status === 'queued' ? 'Waiting for a worker…' : 'Analyzing your code…'}
            </strong>
            <p className="muted small">
              This page updates automatically. You can leave it and come back — the scan keeps
              running.
            </p>
          </div>
        </div>
      )}

      {s.status === 'failed' && (
        <div className="state state-error" role="alert">
          <strong>The scan failed</strong>
          <span>{summary.error ?? 'Unknown error.'}</span>
          <Link to={`/projects/${s.projectId}`}>Back to the project to upload again</Link>
        </div>
      )}

      {s.status === 'failed' && <ProjectOverview scanId={s.id} status={s.status} />}

      {completed && (
        <Tabs
          label="Scan views"
          active={tab}
          onChange={(id) => {
            const next = new URLSearchParams(params);
            if (id === 'dashboard') next.delete('tab');
            else next.set('tab', id);
            setParams(next, { replace: true });
          }}
          tabs={[
            {
              id: 'dashboard',
              label: 'Dashboard & findings',
              content: (
                <>
                  {rollup ? (
                    <Dashboard rollup={rollup} previous={previous} scanId={s.id} />
                  ) : (
                    <p className="muted">This scan has no rollup (it predates the dashboard).</p>
                  )}

                  <section className="card" aria-labelledby="reports-title">
                    <h2 id="reports-title">Reports</h2>
                    <ReportButtons scanId={s.id} />
                  </section>

                  {profile && (
                    <details className="card scan-meta">
                      <summary>Scanned project</summary>
                      <dl>
                        <dt>Languages</dt>
                        <dd>
                          {profile.languages.map((l) => `${l.language} (${l.files})`).join(', ') ||
                            '—'}
                        </dd>
                        <dt>Frameworks</dt>
                        <dd>{profile.frameworks.map((f) => f.name).join(', ') || '—'}</dd>
                        <dt>Files parsed</dt>
                        <dd>
                          {summary.filesParsed ?? 0} of {profile.sourceFiles.length} source files
                          {summary.parseErrors ? ` · ${summary.parseErrors} with parse errors` : ''}
                        </dd>
                        {summary.skippedFileCount ? (
                          <>
                            <dt>Ignored</dt>
                            <dd data-testid="skipped-files">
                              {summary.skippedFileCount.toLocaleString()} dependency/build files
                              {summary.skippedDirs?.length
                                ? ` in ${skippedDirsLabel(summary.skippedDirs)}`
                                : ''}{' '}
                              <span className="muted">(not extracted or scanned)</span>
                            </dd>
                          </>
                        ) : null}
                        {summary.detectorErrors && summary.detectorErrors.length > 0 && (
                          <>
                            <dt>Detector errors</dt>
                            <dd>{summary.detectorErrors.map((d) => d.detectorId).join(', ')}</dd>
                          </>
                        )}
                      </dl>
                    </details>
                  )}

                  {findings.isPending ? (
                    <Loading label="Loading findings…" />
                  ) : findings.isError ? (
                    <ErrorState error={findings.error} onRetry={() => findings.refetch()} />
                  ) : (
                    <FindingsTable findings={findings.data} />
                  )}

                  <InformationalNotes notes={summary.informationalNotes ?? []} />
                </>
              ),
            },
            {
              id: 'overview',
              label: 'Project overview',
              content: <ProjectOverview scanId={s.id} status={s.status} findings={findings.data} />,
            },
          ]}
        />
      )}
    </div>
  );
}
