import type { Finding, RiskGrade, ScanStatus, Severity } from '@webguard/core';
import {
  SEVERITY_LABEL,
  confidenceBand,
  formatPercent,
  isCandidate,
  splitOwasp,
} from '../lib/findings';

/** Severity: a ramp-colored swatch + the word, so meaning never rests on color alone. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge badge-severity sev-${severity}`}>
      <span className="swatch" aria-hidden="true" />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

const BAND_LABEL = { high: 'High confidence', medium: 'Medium confidence', low: 'Low confidence' };

export function ConfidenceBadge({ confidence }: { confidence: number }) {
  const band = confidenceBand(confidence);
  return (
    <span
      className={`badge badge-confidence conf-${band}`}
      title={`Detector confidence ${confidence.toFixed(2)} (${band})`}
    >
      <span className="meter" aria-hidden="true">
        <span style={{ width: `${Math.round(confidence * 100)}%` }} />
      </span>
      {formatPercent(confidence)}
      <span className="visually-hidden"> — {BAND_LABEL[band]}</span>
      {band === 'low' && <span aria-hidden="true"> · low</span>}
    </span>
  );
}

export function OwaspBadge({ category }: { category: string }) {
  const { code, name } = splitOwasp(category);
  return (
    <span className="badge badge-owasp" title={category}>
      <strong>{code}</strong> {name}
    </span>
  );
}

export function CweBadge({ cwe }: { cwe: string | null }) {
  if (!cwe) return null;
  const num = /^CWE-(\d+)$/.exec(cwe)?.[1];
  return num ? (
    <a
      className="badge badge-cwe"
      href={`https://cwe.mitre.org/data/definitions/${num}.html`}
      target="_blank"
      rel="noreferrer noopener"
    >
      {cwe}
    </a>
  ) : (
    <span className="badge badge-cwe">{cwe}</span>
  );
}

/** Labels findings that need a human: candidates and low-confidence results. */
export function ReviewBadges({ finding }: { finding: Pick<Finding, 'evidence' | 'confidence'> }) {
  const candidate = isCandidate(finding);
  const low = confidenceBand(finding.confidence) === 'low';
  if (!candidate && !low) return null;
  return (
    <>
      {candidate && (
        <span className="badge badge-review" title="Heuristic result — confirm manually">
          <span aria-hidden="true">?</span> Candidate
        </span>
      )}
      {low && !candidate && (
        <span className="badge badge-review" title="Below 50% confidence — verify before acting">
          <span aria-hidden="true">?</span> Needs review
        </span>
      )}
    </>
  );
}

const STATUS_LABEL: Record<ScanStatus, string> = {
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
};
const STATUS_ICON: Record<ScanStatus, string> = {
  queued: '◷',
  running: '↻',
  completed: '✓',
  failed: '✕',
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span className={`badge badge-status status-${status}`}>
      <span aria-hidden="true" className={status === 'running' ? 'spin' : undefined}>
        {STATUS_ICON[status]}
      </span>
      {STATUS_LABEL[status]}
    </span>
  );
}

export function GradeBadge({ grade, size = 'md' }: { grade: RiskGrade; size?: 'md' | 'lg' }) {
  return (
    <span className={`grade grade-${grade} grade-${size}`} aria-label={`Risk grade ${grade}`}>
      {grade}
    </span>
  );
}
