import { Link } from 'react-router-dom';
import type { Scan, ScanRollup } from '@webguard/core';
import { SEVERITIES } from '../lib/findings';
import { GradeBadge } from './Badges';
import { OwaspBars } from './charts/OwaspBars';
import { SeverityDonut } from './charts/SeverityDonut';

function Delta({ current, previous, label }: { current: number; previous: number; label: string }) {
  const diff = current - previous;
  if (diff === 0) {
    return (
      <span className="delta delta-flat">
        <span aria-hidden="true">＝</span> no change in {label}
      </span>
    );
  }
  // Fewer findings / lower risk is the good direction.
  const better = diff < 0;
  return (
    <span className={`delta ${better ? 'delta-good' : 'delta-bad'}`}>
      <span aria-hidden="true">{better ? '▼' : '▲'}</span> {Math.abs(diff)}{' '}
      {better ? 'fewer' : 'more'} {label}
    </span>
  );
}

export function TrendTile({
  rollup,
  previous,
  scanId,
}: {
  rollup: ScanRollup;
  previous: Scan | null;
  scanId?: string;
}) {
  const prev = previous?.summary?.rollup;
  return (
    <div className="stat-tile" data-testid="trend-tile">
      <span className="stat-label">Trend vs previous scan</span>
      {prev ? (
        <>
          <span className="stat-value">
            {prev.total} → {rollup.total}
          </span>
          <Delta current={rollup.total} previous={prev.total} label="findings" />
          <Delta current={rollup.riskScore} previous={prev.riskScore} label="risk points" />
          <span className="muted small">
            Previous grade {prev.grade}
            {SEVERITIES.filter((s) => s === 'critical' || s === 'high').map((s) => {
              const d = (rollup.bySeverity[s] ?? 0) - (prev.bySeverity[s] ?? 0);
              return d !== 0 ? ` · ${s} ${d > 0 ? '+' : ''}${d}` : '';
            })}
          </span>
          {scanId && previous && (
            <Link
              className="small"
              to={`/projects/${previous.projectId}/history?scan=${scanId}&against=${previous.id}`}
            >
              See what changed →
            </Link>
          )}
        </>
      ) : (
        <>
          <span className="stat-value muted">—</span>
          <span className="muted small">
            First completed scan of this project — nothing to compare yet.
          </span>
        </>
      )}
    </div>
  );
}

export function Dashboard({
  rollup,
  previous,
  scanId,
}: {
  rollup: ScanRollup;
  previous: Scan | null;
  scanId?: string;
}) {
  return (
    <div className="dashboard" data-testid="dashboard">
      <div className="stat-row">
        <div className="stat-tile">
          <span className="stat-label">Total findings</span>
          <span className="stat-value" data-testid="total-findings">
            {rollup.total}
          </span>
          <span className="muted small">
            {rollup.bySeverity.critical} critical · {rollup.bySeverity.high} high
          </span>
        </div>
        <div className="stat-tile">
          <span className="stat-label">Risk grade</span>
          <span className="stat-value grade-row">
            <GradeBadge grade={rollup.grade} size="lg" />
            <span className="small muted">score {rollup.riskScore}/100</span>
          </span>
          <span className="muted small">{rollup.gradeReason}</span>
        </div>
        <TrendTile rollup={rollup} previous={previous} scanId={scanId} />
      </div>
      <div className="chart-row">
        <SeverityDonut rollup={rollup} />
        <OwaspBars rollup={rollup} />
      </div>
    </div>
  );
}
