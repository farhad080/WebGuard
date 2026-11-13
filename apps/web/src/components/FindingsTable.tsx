import type { Finding, OwaspCategory, Severity } from '@webguard/core';
import { useMemo } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  findingTitle,
  formatLocation,
  OWASP_CATEGORIES,
  SEVERITIES,
  SEVERITY_LABEL,
  SEVERITY_RANK,
  compareBySeverity,
  needsReview,
  splitOwasp,
} from '../lib/findings';
import { ConfidenceBadge, OwaspBadge, ReviewBadges, SeverityBadge } from './Badges';
import { FileViewer } from './code/FileViewer';
import { EmptyState } from './States';

type SortKey = 'severity' | 'confidence' | 'file';

const MIN_CONFIDENCE_OPTIONS = [
  { value: '0', label: 'Any' },
  { value: '0.5', label: '≥ 50% (medium+)' },
  { value: '0.8', label: '≥ 80% (high)' },
];

export interface FindingFilters {
  severity: Severity[];
  owasp: OwaspCategory | '';
  minConfidence: number;
  file: string;
  sort: SortKey;
}

function readFilters(params: URLSearchParams): FindingFilters {
  const sev = (params.get('severity') ?? '')
    .split(',')
    .filter((s): s is Severity => (SEVERITIES as string[]).includes(s));
  const owasp = params.get('owasp') ?? '';
  const min = Number(params.get('minConfidence') ?? 0);
  const sort = params.get('sort');
  return {
    severity: sev,
    owasp: (OWASP_CATEGORIES as string[]).includes(owasp) ? (owasp as OwaspCategory) : '',
    minConfidence: Number.isFinite(min) && min >= 0 && min <= 1 ? min : 0,
    file: params.get('file') ?? '',
    sort: sort === 'confidence' || sort === 'file' ? sort : 'severity',
  };
}

export function applyFilters(findings: Finding[], f: FindingFilters): Finding[] {
  const file = f.file.trim().toLowerCase();
  const out = findings.filter(
    (x) =>
      (f.severity.length === 0 || f.severity.includes(x.severity)) &&
      (!f.owasp || x.owaspCategory === f.owasp) &&
      x.confidence >= f.minConfidence &&
      (!file || x.filePath.toLowerCase().includes(file)),
  );
  const cmp: Record<SortKey, (a: Finding, b: Finding) => number> = {
    severity: compareBySeverity,
    confidence: (a, b) => b.confidence - a.confidence || compareBySeverity(a, b),
    file: (a, b) =>
      a.filePath.localeCompare(b.filePath) ||
      a.lineStart - b.lineStart ||
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity],
  };
  return out.sort(cmp[f.sort]);
}

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [params, setParams] = useSearchParams();
  const filters = readFilters(params);
  const rows = applyFilters(findings, filters);

  // The file viewer is URL state (?view=<findingId>): Back closes it, and it can be linked.
  const viewing = params.get('view');
  const viewed = viewing ? findings.find((f) => f.id === viewing) : undefined;
  const viewedFile = viewed?.filePath;
  const fileFindings = useMemo(
    () => (viewedFile ? findings.filter((f) => f.filePath === viewedFile) : []),
    [findings, viewedFile],
  );
  const openViewer = (id: string, replace = false) => {
    const next = new URLSearchParams(params);
    next.set('view', id);
    setParams(next, { replace });
  };
  const closeViewer = () => {
    const next = new URLSearchParams(params);
    next.delete('view');
    setParams(next, { replace: true });
  };

  const update = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === '' || v === '0') next.delete(k);
      else next.set(k, v);
    }
    setParams(next, { replace: true });
  };

  const toggleSeverity = (s: Severity) => {
    const set = new Set(filters.severity);
    if (set.has(s)) set.delete(s);
    else set.add(s);
    update({ severity: SEVERITIES.filter((x) => set.has(x)).join(',') || null });
  };

  const active =
    filters.severity.length > 0 || filters.owasp || filters.minConfidence > 0 || filters.file;
  const reviewCount = rows.filter(needsReview).length;

  const sortHeader = (key: SortKey, label: string) => (
    <th
      scope="col"
      aria-sort={filters.sort === key ? (key === 'file' ? 'ascending' : 'descending') : 'none'}
    >
      <button
        type="button"
        className="sort-btn"
        onClick={() => update({ sort: key === 'severity' ? null : key })}
      >
        {label}
        <span aria-hidden="true">{filters.sort === key ? (key === 'file' ? ' ▲' : ' ▼') : ''}</span>
      </button>
    </th>
  );

  return (
    <section aria-labelledby="findings-title" className="findings">
      <h2 id="findings-title">Findings</h2>
      <form
        className="filter-bar"
        role="search"
        aria-label="Filter findings"
        onSubmit={(e) => e.preventDefault()}
      >
        <fieldset className="sev-filter">
          <legend>Severity</legend>
          {SEVERITIES.map((s) => (
            <label key={s} className="chip">
              <input
                type="checkbox"
                checked={filters.severity.includes(s)}
                onChange={() => toggleSeverity(s)}
              />
              <span className={`swatch sev-${s}`} aria-hidden="true" />
              {SEVERITY_LABEL[s]}
            </label>
          ))}
        </fieldset>
        <label className="field">
          <span>OWASP category</span>
          <select value={filters.owasp} onChange={(e) => update({ owasp: e.target.value || null })}>
            <option value="">All categories</option>
            {OWASP_CATEGORIES.map((c) => {
              const { code, name } = splitOwasp(c);
              return (
                <option key={c} value={c}>
                  {code} {name}
                </option>
              );
            })}
          </select>
        </label>
        <label className="field">
          <span>Min confidence</span>
          <select
            value={String(filters.minConfidence)}
            onChange={(e) => update({ minConfidence: e.target.value })}
          >
            {MIN_CONFIDENCE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>File</span>
          <input
            type="search"
            placeholder="path contains…"
            value={filters.file}
            onChange={(e) => update({ file: e.target.value || null })}
          />
        </label>
        {active && (
          <button
            type="button"
            className="btn btn-small btn-ghost"
            onClick={() => setParams(new URLSearchParams(), { replace: true })}
          >
            Clear filters
          </button>
        )}
      </form>

      <p className="muted small" aria-live="polite" data-testid="findings-count">
        Showing {rows.length} of {findings.length} findings
        {reviewCount > 0 && ` · ${reviewCount} need manual review (candidate or low confidence)`}
      </p>

      {findings.length === 0 ? (
        <EmptyState title="No findings">
          The detectors found nothing to report in this scan.
        </EmptyState>
      ) : rows.length === 0 ? (
        <EmptyState title="No findings match these filters" />
      ) : (
        <div className="table-wrap">
          <table className="data-table findings-table">
            <thead>
              <tr>
                {sortHeader('severity', 'Severity')}
                {sortHeader('confidence', 'Confidence')}
                <th scope="col">Category</th>
                {sortHeader('file', 'Location')}
                <th scope="col">Issue</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.id} className={needsReview(f) ? 'row-review' : undefined}>
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
                    <button
                      type="button"
                      className="location-link"
                      title={`Open ${formatLocation(f)}`}
                      aria-label={`Open ${f.filePath} at line ${f.lineStart}`}
                      aria-haspopup="dialog"
                      onClick={() => openViewer(f.id)}
                    >
                      {formatLocation(f)}
                    </button>
                  </td>
                  <td>
                    <Link to={`/findings/${f.id}`} className="finding-link">
                      {findingTitle(f)}
                    </Link>{' '}
                    <ReviewBadges finding={f} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {viewed && (
        <FileViewer
          scanId={viewed.scanId}
          path={viewed.filePath}
          finding={viewed}
          fileFindings={fileFindings}
          onSelect={(id) => openViewer(id, true)}
          onClose={closeViewer}
        />
      )}
    </section>
  );
}
