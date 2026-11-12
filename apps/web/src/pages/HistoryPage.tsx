import { useQuery } from '@tanstack/react-query';
import type { Finding, Scan, ScanComparison, ScanRef } from '@webguard/core';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { api } from '../api/endpoints';
import {
  ConfidenceBadge,
  GradeBadge,
  OwaspBadge,
  ReviewBadges,
  SeverityBadge,
} from '../components/Badges';
import { RiskTrend } from '../components/charts/RiskTrend';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { Tabs } from '../components/Tabs';
import { formatDateTime } from '../lib/findings';

function DiffTable({
  rows,
  empty,
}: {
  rows: { finding: Finding; note?: string }[];
  empty: string;
}) {
  if (rows.length === 0) return <p className="muted">{empty}</p>;
  return (
    <div className="table-wrap">
      <table className="data-table findings-table">
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Confidence</th>
            <th scope="col">Category</th>
            <th scope="col">Location</th>
            <th scope="col">Issue</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ finding: f, note }) => (
            <tr key={f.id}>
              <td>
                <SeverityBadge severity={f.severity} />
              </td>
              <td>
                <ConfidenceBadge confidence={f.confidence} />
              </td>
              <td>
                <OwaspBadge category={f.owaspCategory} />
              </td>
              <td className="mono location">
                {f.filePath}:{f.lineStart}
                {note && <span className="muted small"> {note}</span>}
              </td>
              <td>
                <Link to={`/findings/${f.id}`} className="finding-link">
                  {f.remediation?.title ?? f.explanation.split('. ')[0]}
                </Link>{' '}
                <ReviewBadges finding={f} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CompareResult({ data }: { data: ScanComparison }) {
  const { summary } = data;
  const delta = summary.riskScoreDelta;
  return (
    <div className="stack" data-testid="compare-result">
      <div className="stat-row">
        <div className="stat-tile">
          <span className="stat-label">Fixed</span>
          <span className="stat-value">{summary.fixed}</span>
          <span className={`delta ${summary.fixed > 0 ? 'delta-good' : 'delta-flat'}`}>
            <span aria-hidden="true">{summary.fixed > 0 ? '✓' : '＝'}</span> resolved since the
            baseline
          </span>
        </div>
        <div className="stat-tile">
          <span className="stat-label">New</span>
          <span className="stat-value">{summary.new}</span>
          <span className={`delta ${summary.new > 0 ? 'delta-bad' : 'delta-flat'}`}>
            <span aria-hidden="true">{summary.new > 0 ? '▲' : '＝'}</span> introduced since the
            baseline
          </span>
        </div>
        <div className="stat-tile">
          <span className="stat-label">Still open</span>
          <span className="stat-value">{summary.persisting}</span>
          <span className="muted small">
            Risk {data.against.rollup?.riskScore ?? '—'} → {data.scan.rollup?.riskScore ?? '—'}
            {delta !== null && delta !== 0 && ` (${delta > 0 ? '+' : ''}${delta})`}
          </span>
        </div>
      </div>
      <Tabs
        label="Comparison"
        tabs={[
          {
            id: 'new',
            label: `New (${summary.new})`,
            content: (
              <DiffTable rows={data.new.map((finding) => ({ finding }))} empty="No new findings." />
            ),
          },
          {
            id: 'fixed',
            label: `Fixed (${summary.fixed})`,
            content: (
              <DiffTable
                rows={data.fixed.map((finding) => ({ finding }))}
                empty="Nothing was fixed between these scans."
              />
            ),
          },
          {
            id: 'open',
            label: `Still open (${summary.persisting})`,
            content: (
              <DiffTable
                rows={data.persisting.map(({ finding, previous }) => ({
                  finding,
                  note:
                    previous.lineStart !== finding.lineStart
                      ? `(was line ${previous.lineStart})`
                      : undefined,
                }))}
                empty="No findings carried over."
              />
            ),
          },
        ]}
      />
    </div>
  );
}

function ScanLabel({ scan }: { scan: ScanRef }) {
  return (
    <span className="scan-label">
      {scan.rollup && <GradeBadge grade={scan.rollup.grade} />} {formatDateTime(scan.createdAt)}
    </span>
  );
}

function ScanOption({ scan }: { scan: Scan }) {
  const r = scan.summary?.rollup;
  return (
    <option value={scan.id}>
      {formatDateTime(scan.createdAt)}
      {r ? ` — grade ${r.grade}, ${r.total} findings` : ''}
    </option>
  );
}

export function HistoryPage() {
  const { projectId = '' } = useParams();
  const [params, setParams] = useSearchParams();
  const project = useQuery({
    queryKey: ['project', projectId],
    queryFn: () => api.getProject(projectId),
  });
  const scans = useQuery({
    queryKey: ['scans', projectId],
    queryFn: () => api.listScans(projectId),
    enabled: project.isSuccess,
    // Always current: scans may have finished since the list was last cached.
    refetchOnMount: 'always',
  });

  const completed = (scans.data ?? [])
    .filter((s) => s.status === 'completed')
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  const ids = new Set(completed.map((s) => s.id));
  const target = ids.has(params.get('scan') ?? '') ? params.get('scan')! : completed[0]?.id;
  const base = ids.has(params.get('against') ?? '')
    ? params.get('against')!
    : completed.find((s) => s.id !== target)?.id;

  const comparison = useQuery({
    queryKey: ['compare', target, base],
    queryFn: () => api.compareScans(target!, base!),
    enabled: !!target && !!base && target !== base,
  });

  const select = (key: 'scan' | 'against', value: string) => {
    const next = new URLSearchParams(params);
    next.set('scan', key === 'scan' ? value : (target ?? ''));
    next.set('against', key === 'against' ? value : (base ?? ''));
    setParams(next, { replace: true });
  };

  if (project.isPending) return <Loading label="Loading project…" />;
  if (project.isError) return <ErrorState title="Project unavailable" error={project.error} />;

  return (
    <div className="page">
      <nav aria-label="Breadcrumb" className="crumbs">
        <Link to="/projects">Projects</Link> <span aria-hidden="true">/</span>{' '}
        <Link to={`/projects/${projectId}`}>{project.data.name}</Link>{' '}
        <span aria-hidden="true">/</span> <span aria-current="page">History</span>
      </nav>
      <h1>History &amp; compare</h1>

      {scans.isPending ? (
        <Loading label="Loading scans…" />
      ) : scans.isError ? (
        <ErrorState error={scans.error} onRetry={() => scans.refetch()} />
      ) : completed.length === 0 ? (
        <EmptyState
          title="No completed scans yet"
          action={<Link to={`/projects/${projectId}`}>Upload a ZIP</Link>}
        />
      ) : (
        <>
          <RiskTrend scans={completed} />

          <section className="card stack" aria-labelledby="compare-title">
            <h2 id="compare-title">Compare two scans</h2>
            {completed.length < 2 ? (
              <p className="muted">Run at least two scans of this project to compare them.</p>
            ) : (
              <>
                <div className="compare-pickers">
                  <label className="field grow">
                    <span>Baseline</span>
                    <select value={base} onChange={(e) => select('against', e.target.value)}>
                      {completed.map((s) => (
                        <ScanOption key={s.id} scan={s} />
                      ))}
                    </select>
                  </label>
                  <span aria-hidden="true" className="compare-arrow">
                    →
                  </span>
                  <label className="field grow">
                    <span>Compared scan</span>
                    <select value={target} onChange={(e) => select('scan', e.target.value)}>
                      {completed.map((s) => (
                        <ScanOption key={s.id} scan={s} />
                      ))}
                    </select>
                  </label>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => {
                      const next = new URLSearchParams(params);
                      next.set('scan', base ?? '');
                      next.set('against', target ?? '');
                      setParams(next, { replace: true });
                    }}
                  >
                    Swap
                  </button>
                </div>
                {target === base ? (
                  <p className="muted">Pick two different scans.</p>
                ) : comparison.isPending ? (
                  <Loading label="Comparing…" />
                ) : comparison.isError ? (
                  <ErrorState error={comparison.error} onRetry={() => comparison.refetch()} />
                ) : (
                  <>
                    <p className="small muted">
                      <ScanLabel scan={comparison.data.against} /> →{' '}
                      <ScanLabel scan={comparison.data.scan} />
                    </p>
                    <CompareResult data={comparison.data} />
                  </>
                )}
              </>
            )}
          </section>
        </>
      )}
    </div>
  );
}
