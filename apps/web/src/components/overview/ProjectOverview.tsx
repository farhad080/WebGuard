import { useQuery } from '@tanstack/react-query';
import type {
  Finding,
  FileRank,
  OwaspCategory,
  ProjectStats,
  ScanStatus,
  StatsStage,
} from '@webguard/core';
import { useMemo, useState, type ReactNode } from 'react';
import { api } from '../../api/endpoints';
import {
  formatBytes,
  formatDateTime,
  SEVERITIES,
  SEVERITY_LABEL,
  SEVERITY_RANK,
  splitOwasp,
} from '../../lib/findings';
import { GradeBadge } from '../Badges';
import { FileViewer } from '../code/FileViewer';
import { EmptyState, ErrorState, Loading } from '../States';
import { FolderTree } from './FolderTree';
import { formatCount, formatMs, languageName, percent } from './format';
import { LanguagesChart } from './LanguagesChart';

const STAGE_TEXT: Record<StatsStage, string> = {
  upload: 'before the archive could be extracted',
  extraction: 'after extraction, during analysis',
  analysis: 'after analysis, while saving the results',
  complete: '',
};

/**
 * Project Overview: the statistics computed once during the scan (GET /api/scans/:id/stats),
 * as tiles, charts, a severity-colored folder tree, and dependency / security / scan panels.
 * Files in the tree and the file lists open the shared file viewer.
 */
export function ProjectOverview({
  scanId,
  status,
  findings,
}: {
  scanId: string;
  status: ScanStatus;
  /** The scan's findings (for the file viewer's marks); absent for a failed scan. */
  findings?: readonly Finding[];
}) {
  const final = status === 'completed' || status === 'failed';
  const query = useQuery({
    queryKey: ['stats', scanId],
    queryFn: () => api.getStats(scanId),
    enabled: final,
    staleTime: Infinity,
  });
  const [viewing, setViewing] = useState<{ path: string; findingId: string | null } | null>(null);

  const fileFindings = useMemo(
    () => (viewing && findings ? findings.filter((f) => f.filePath === viewing.path) : []),
    [findings, viewing],
  );
  const openFile = (path: string) => {
    // Focus the file's most severe finding, if it has any.
    const worst = (findings ?? [])
      .filter((f) => f.filePath === path)
      .sort(
        (a, b) =>
          SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.lineStart - b.lineStart,
      )[0];
    setViewing({ path, findingId: worst?.id ?? null });
  };

  if (!final) {
    return (
      <EmptyState title="Overview not ready yet">
        Project statistics are computed during the scan and appear when it finishes.
      </EmptyState>
    );
  }
  if (query.isPending) return <Loading label="Loading project overview…" />;
  if (query.isError) {
    return (
      <ErrorState
        title="Project overview unavailable"
        error={query.error}
        onRetry={() => query.refetch()}
      />
    );
  }
  const stats = query.data.stats;
  if (!stats) {
    return (
      <EmptyState title="No statistics for this scan">
        {status === 'failed'
          ? 'The scan failed before any statistics were gathered.'
          : 'This scan predates the Project Overview. Re-scan the project to compute them.'}
      </EmptyState>
    );
  }

  return (
    <div className="overview" data-testid="project-overview">
      {stats.status === 'partial' && (
        <p className="notice" role="note" data-testid="partial-stats">
          <strong>Partial statistics.</strong> The scan failed {STAGE_TEXT[stats.stage]}, so only
          what was gathered before that is shown.
          {query.data.error && <> Reason: {query.data.error}</>}
        </p>
      )}

      <Tiles stats={stats} />

      <div className="overview-grid">
        <LanguagesChart languages={stats.languages} />
        <LocCard stats={stats} />
      </div>

      <div className="overview-grid">
        <section className="card" aria-labelledby="tree-title">
          <h3 id="tree-title">File structure</h3>
          {stats.tree ? (
            <>
              <p className="muted small">
                Folders are marked with the worst severity found inside them. Select a file to open
                it.
              </p>
              <SeverityKey />
              <FolderTree root={stats.tree} onOpenFile={openFile} />
            </>
          ) : (
            <p className="muted">Not available: the scan stopped before the files were profiled.</p>
          )}
        </section>
        <div className="overview-stack">
          <StackCard stats={stats} />
          <FilesCard stats={stats} onOpenFile={openFile} />
        </div>
      </div>

      <div className="overview-grid">
        <DependenciesCard stats={stats} />
        <SecurityCard stats={stats} onOpenFile={openFile} />
      </div>

      <ScanInfoCard stats={stats} />

      {viewing && (
        <FileViewer
          scanId={scanId}
          path={viewing.path}
          finding={fileFindings.find((f) => f.id === viewing.findingId) ?? null}
          fileFindings={fileFindings}
          onSelect={(id) => setViewing({ path: viewing.path, findingId: id })}
          onClose={() => setViewing(null)}
        />
      )}
    </div>
  );
}

function Tile({
  label,
  value,
  sub,
  testId,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  testId?: string;
}) {
  return (
    <div className="stat-tile" data-testid={testId}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {sub && <span className="muted small">{sub}</span>}
    </div>
  );
}

function Tiles({ stats }: { stats: ProjectStats }) {
  const { size, dependencies: deps, security, skipped } = stats;
  const skippedTotal =
    skipped.ignoredDirFiles + skipped.binary + skipped.tooLarge + skipped.unrecognized;
  return (
    <div className="stat-row overview-tiles" data-testid="overview-tiles">
      <Tile
        label="Files"
        value={formatCount(size.files)}
        sub={skippedTotal > 0 ? `${skippedTotal.toLocaleString()} not analyzed` : 'all analyzed'}
        testId="tile-files"
      />
      <Tile label="Folders" value={formatCount(size.folders)} testId="tile-folders" />
      <Tile
        label="Lines of code"
        value={formatCount(size.loc?.total)}
        sub={size.loc ? `${size.loc.code.toLocaleString()} code` : undefined}
        testId="tile-loc"
      />
      <Tile
        label="Unpacked size"
        value={size.unpackedBytes === null ? '—' : formatBytes(size.unpackedBytes)}
        sub={size.zipBytes === null ? undefined : `${formatBytes(size.zipBytes)} ZIP`}
        testId="tile-size"
      />
      <Tile
        label="Dependencies"
        value={formatCount(deps?.total)}
        sub={deps ? `${deps.direct} direct · ${deps.transitive} transitive` : undefined}
        testId="tile-deps"
      />
      <Tile
        label="Risk grade"
        value={
          security ? (
            <span className="grade-row">
              <GradeBadge grade={security.grade} size="lg" />
              <span className="small muted">score {security.riskScore}/100</span>
            </span>
          ) : (
            '—'
          )
        }
        testId="tile-grade"
      />
    </div>
  );
}

/** Code vs comment vs blank: one series (share of lines) per row, value in text ink. */
function LocCard({ stats }: { stats: ProjectStats }) {
  const loc = stats.size.loc;
  return (
    <section className="card" aria-labelledby="loc-title">
      <h3 id="loc-title">Lines of code</h3>
      {!loc || loc.total === 0 ? (
        <p className="muted">No lines counted.</p>
      ) : (
        <>
          <ul className="share-list" data-testid="loc-breakdown">
            {(['code', 'comment', 'blank'] as const).map((k) => (
              <li key={k}>
                <span className="share-label">{k[0]!.toUpperCase() + k.slice(1)}</span>
                <span className="share-bar" aria-hidden="true">
                  <span style={{ width: percent(loc[k], loc.total) }} />
                </span>
                <span className="share-value">
                  {loc[k].toLocaleString()}{' '}
                  <span className="muted small">({percent(loc[k], loc.total)})</span>
                </span>
              </li>
            ))}
          </ul>
          <h4>Analysis depth by language</h4>
          <ul className="depth-list" data-testid="analysis-depth">
            {stats.languages.map((l) => (
              <li key={l.language}>
                <span>{languageName(l.language)}</span>
                <span
                  className={`badge ${l.analysisDepth === 'full-ast' ? 'badge-depth-full' : 'badge-neutral'}`}
                >
                  {l.analysisLabel}
                </span>
              </li>
            ))}
          </ul>
          {stats.languages.some((l) => l.analysisDepth === 'pattern-only') && (
            <p className="muted small">
              Only JavaScript and TypeScript get data-flow (taint) analysis. Other languages are
              checked for secrets, weak crypto, dependencies and configuration, so a clean result
              there is a shallower guarantee.
            </p>
          )}
        </>
      )}
    </section>
  );
}

function StackCard({ stats }: { stats: ProjectStats }) {
  const stack = stats.stack;
  return (
    <section className="card" aria-labelledby="stack-title">
      <h3 id="stack-title">Stack</h3>
      {!stack ? (
        <p className="muted">Not available for this scan.</p>
      ) : (
        <dl className="kv">
          <dt>Frameworks</dt>
          <dd>{stack.frameworks.map((f) => f.name).join(', ') || '—'}</dd>
          <dt>Entry point</dt>
          <dd className="mono">{stack.entryPoints.join(', ') || '—'}</dd>
          <dt>Package manager</dt>
          <dd>
            {stack.packageManagers.length === 0
              ? '—'
              : stack.packageManagers
                  .map((p) =>
                    p.lockfile ? `${p.name} (${p.lockfile})` : `${p.name} (no lockfile)`,
                  )
                  .join(', ')}
          </dd>
        </dl>
      )}
    </section>
  );
}

function FileList({
  files,
  measure,
  onOpenFile,
}: {
  files: FileRank[];
  measure: 'bytes' | 'lines';
  onOpenFile: (path: string) => void;
}) {
  if (files.length === 0) return <p className="muted small">—</p>;
  return (
    <ol className="rank-list">
      {files.map((f) => (
        <li key={f.path}>
          <button
            type="button"
            className="location-link"
            onClick={() => onOpenFile(f.path)}
            aria-label={`Open ${f.path}`}
          >
            {f.path}
          </button>
          <span className="muted small">
            {measure === 'bytes' ? formatBytes(f.bytes) : `${formatCount(f.lines)} lines`}
          </span>
        </li>
      ))}
    </ol>
  );
}

function FilesCard({
  stats,
  onOpenFile,
}: {
  stats: ProjectStats;
  onOpenFile: (path: string) => void;
}) {
  return (
    <section className="card" aria-labelledby="files-title">
      <h3 id="files-title">Largest & longest files</h3>
      <div className="two-col">
        <div>
          <h4>By size</h4>
          <FileList files={stats.size.largestFiles} measure="bytes" onOpenFile={onOpenFile} />
        </div>
        <div>
          <h4>By lines</h4>
          <FileList files={stats.size.longestFiles} measure="lines" onOpenFile={onOpenFile} />
        </div>
      </div>
    </section>
  );
}

function DependenciesCard({ stats }: { stats: ProjectStats }) {
  const deps = stats.dependencies;
  return (
    <section className="card" aria-labelledby="deps-title" data-testid="deps-panel">
      <h3 id="deps-title">Dependencies</h3>
      {!deps ? (
        <p className="muted">Not available for this scan.</p>
      ) : deps.total === 0 && deps.manifests.length === 0 ? (
        <p className="muted">No npm manifest or lockfile found.</p>
      ) : (
        <>
          <dl className="kv kv-numbers">
            <dt>Direct</dt>
            <dd>{deps.direct.toLocaleString()}</dd>
            <dt>Transitive</dt>
            <dd>{deps.transitive.toLocaleString()}</dd>
            <dt>Vulnerable</dt>
            <dd>{deps.vulnerable.toLocaleString()}</dd>
            <dt>End-of-life / outdated</dt>
            <dd>{deps.outdated.toLocaleString()}</dd>
            <dt>Suspected typosquats</dt>
            <dd>{deps.typosquats.length.toLocaleString()}</dd>
          </dl>
          {deps.typosquats.length > 0 && (
            <ul className="typosquats">
              {deps.typosquats.map((t) => (
                <li key={t.name}>
                  <span className="mono">{t.name}</span>
                  {t.target && (
                    <span className="muted">
                      {' '}
                      — did you mean <span className="mono">{t.target}</span>?
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
          <p className="muted small">
            From {deps.manifests.join(', ') || 'no manifest'}. Vulnerability data: the bundled
            advisory snapshot (plus OSV.dev when enabled).
          </p>
        </>
      )}
    </section>
  );
}

function SecurityCard({
  stats,
  onOpenFile,
}: {
  stats: ProjectStats;
  onOpenFile: (path: string) => void;
}) {
  const sec = stats.security;
  const skipped = stats.skipped;
  const owasp = sec
    ? (Object.entries(sec.byOwaspCategory) as [OwaspCategory, number][])
        .filter(([, n]) => n > 0)
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    : [];
  const maxSev = sec ? Math.max(1, ...SEVERITIES.map((s) => sec.bySeverity[s])) : 1;
  return (
    <section className="card" aria-labelledby="security-title" data-testid="security-panel">
      <h3 id="security-title">Security at a glance</h3>
      {!sec ? (
        <p className="muted">Not available: the scan did not finish its analysis.</p>
      ) : (
        <>
          <p className="small">
            <GradeBadge grade={sec.grade} /> {sec.total} {sec.total === 1 ? 'finding' : 'findings'}{' '}
            · risk score {sec.riskScore}/100
            {/* The plain reason just restates the score; show it only when it adds something
                (e.g. the critical-finding cap). */}
            {!sec.gradeReason.startsWith('risk score') && (
              <span className="muted"> ({sec.gradeReason})</span>
            )}
          </p>
          <h4>By severity</h4>
          <ul className="share-list" data-testid="severity-breakdown">
            {SEVERITIES.map((s) => (
              <li key={s}>
                <span className="share-label">
                  <span className={`swatch sev-${s}`} aria-hidden="true" /> {SEVERITY_LABEL[s]}
                </span>
                <span className={`share-bar sev-bar-${s}`} aria-hidden="true">
                  <span style={{ width: `${(sec.bySeverity[s] / maxSev) * 100}%` }} />
                </span>
                <span className="share-value">{sec.bySeverity[s]}</span>
              </li>
            ))}
          </ul>
          {owasp.length > 0 && (
            <>
              <h4>By OWASP category</h4>
              <ul className="plain-list small">
                {owasp.map(([cat, n]) => {
                  const { code, name } = splitOwasp(cat);
                  return (
                    <li key={cat}>
                      <strong>{code}</strong> {name} <span className="muted">· {n}</span>
                    </li>
                  );
                })}
              </ul>
            </>
          )}
          {sec.topFiles.length > 0 && (
            <>
              <h4>Files with the most findings</h4>
              <ol className="rank-list" data-testid="top-files">
                {sec.topFiles.map((f) => (
                  <li key={f.path}>
                    <button
                      type="button"
                      className="location-link"
                      onClick={() => onOpenFile(f.path)}
                      aria-label={`Open ${f.path}`}
                    >
                      {f.path}
                    </button>
                    <span className="small">
                      <span className={`swatch sev-${f.worstSeverity}`} aria-hidden="true" />{' '}
                      {f.findings} · worst {SEVERITY_LABEL[f.worstSeverity].toLowerCase()}
                    </span>
                  </li>
                ))}
              </ol>
            </>
          )}
        </>
      )}
      <h4>Not analyzed</h4>
      <dl className="kv kv-numbers" data-testid="skipped-summary">
        <dt>In ignored folders</dt>
        <dd>
          {skipped.ignoredDirFiles.toLocaleString()}
          {skipped.ignoredDirs.length > 0 && (
            <span className="muted small">
              {' '}
              ({skipped.ignoredDirs.slice(0, 4).join(', ')}
              {skipped.ignoredDirs.length > 4 ? ` +${skipped.ignoredDirs.length - 4} more` : ''})
            </span>
          )}
        </dd>
        <dt>Binary files</dt>
        <dd>{skipped.binary.toLocaleString()}</dd>
        <dt>Over the size limit</dt>
        <dd>{skipped.tooLarge.toLocaleString()}</dd>
        <dt>Unrecognized format</dt>
        <dd>{skipped.unrecognized.toLocaleString()}</dd>
        {skipped.unsupportedEntries > 0 && (
          <>
            <dt>Symlinks / special entries</dt>
            <dd>{skipped.unsupportedEntries.toLocaleString()}</dd>
          </>
        )}
      </dl>
    </section>
  );
}

function ScanInfoCard({ stats }: { stats: ProjectStats }) {
  const s = stats.scan;
  return (
    <section className="card" aria-labelledby="scaninfo-title" data-testid="scan-info">
      <h3 id="scaninfo-title">Scan info</h3>
      <dl className="kv">
        <dt>Started</dt>
        <dd>{formatDateTime(s.startedAt)}</dd>
        <dt>Finished</dt>
        <dd>{formatDateTime(s.finishedAt)}</dd>
        <dt>Duration</dt>
        <dd>{formatMs(s.durationMs)}</dd>
        <dt>Files parsed</dt>
        <dd>
          {formatCount(s.filesParsed)}
          {s.parseErrors ? ` (${s.parseErrors} with parse errors)` : ''}
        </dd>
        <dt>Detector rules run</dt>
        <dd>
          {s.rules.length === 0 ? (
            'none'
          ) : (
            <details>
              <summary>{s.rules.length} rules</summary>
              <ul className="plain-list mono small">
                {s.rules.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            </details>
          )}
        </dd>
      </dl>
    </section>
  );
}

function SeverityKey() {
  return (
    <ul className="severity-key small" aria-label="Severity colors">
      {SEVERITIES.map((s) => (
        <li key={s}>
          <span className={`swatch sev-${s}`} aria-hidden="true" /> {SEVERITY_LABEL[s]}
        </li>
      ))}
      <li>
        <span className="tree-sev tree-sev-none" aria-hidden="true" /> None
      </li>
    </ul>
  );
}
