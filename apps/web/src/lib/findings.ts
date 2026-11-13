import type { Finding, OwaspCategory, Severity } from '@webguard/core';

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export const OWASP_CATEGORIES: OwaspCategory[] = [
  'A01:2025-Broken Access Control',
  'A02:2025-Security Misconfiguration',
  'A03:2025-Software Supply Chain Failures',
  'A04:2025-Cryptographic Failures',
  'A05:2025-Injection',
  'A06:2025-Insecure Design',
  'A07:2025-Authentication Failures',
  'A08:2025-Software or Data Integrity Failures',
  'A09:2025-Logging and Alerting Failures',
  'A10:2025-Mishandling of Exceptional Conditions',
];

/** "A05:2025-Injection" → { code: "A05", name: "Injection" }. */
export function splitOwasp(category: string): { code: string; name: string } {
  const m = /^(A\d{2}):\d{4}-(.+)$/.exec(category);
  return m ? { code: m[1]!, name: m[2]! } : { code: category, name: category };
}

export type ConfidenceBand = 'high' | 'medium' | 'low';

/** Same bands as the reports: high ≥ 0.8, medium ≥ 0.5, low below. */
export function confidenceBand(confidence: number): ConfidenceBand {
  if (confidence >= 0.8) return 'high';
  if (confidence >= 0.5) return 'medium';
  return 'low';
}

/** Route-level heuristics (e.g. missing authorization) that need manual confirmation. */
export function isCandidate(finding: Pick<Finding, 'evidence'>): boolean {
  return finding.evidence.some((e) => /^candidate\b/i.test(e));
}

export function needsReview(finding: Pick<Finding, 'evidence' | 'confidence'>): boolean {
  return isCandidate(finding) || confidenceBand(finding.confidence) === 'low';
}

/** Most severe first, then most confident, then by location. */
export function compareBySeverity(a: Finding, b: Finding): number {
  return (
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    b.confidence - a.confidence ||
    a.filePath.localeCompare(b.filePath) ||
    a.lineStart - b.lineStart
  );
}

export function formatPercent(fraction: number): string {
  return `${Math.round(fraction * 100)}%`;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function formatDuration(startIso: string | null, endIso: string | null): string | null {
  if (!startIso || !endIso) return null;
  const ms = new Date(endIso).getTime() - new Date(startIso).getTime();
  if (!Number.isFinite(ms) || ms < 0) return null;
  if (ms < 1000) return `${ms} ms`;
  const s = Math.round(ms / 100) / 10;
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
}

export function languageForPath(path: string): string {
  const ext = path.split('.').pop()?.toLowerCase() ?? '';
  const map: Record<string, string> = {
    js: 'javascript',
    mjs: 'javascript',
    cjs: 'javascript',
    jsx: 'javascript',
    ts: 'typescript',
    tsx: 'typescript',
    mts: 'typescript',
    cts: 'typescript',
    // Monaco's JSON highlighting ships with its language service (not loaded); JS reads fine.
    json: 'javascript',
    html: 'html',
    htm: 'html',
    css: 'css',
    scss: 'scss',
    py: 'python',
    php: 'php',
    rb: 'ruby',
    java: 'java',
    go: 'go',
    cs: 'csharp',
    yml: 'yaml',
    yaml: 'yaml',
    xml: 'xml',
    sql: 'sql',
    sh: 'shell',
    md: 'markdown',
    vue: 'html',
    svelte: 'html',
    tf: 'hcl',
  };
  if (/(^|\/)dockerfile$/i.test(path)) return 'dockerfile';
  return map[ext] ?? 'plaintext';
}

/** One-line title of a finding: its remediation title, else the explanation's first sentence. */
export function findingTitle(f: Pick<Finding, 'remediation' | 'explanation'>): string {
  return f.remediation?.title ?? f.explanation.split('. ')[0] ?? f.explanation;
}

/** `file:13` or `file:13–15`. */
export function formatLocation(f: Pick<Finding, 'filePath' | 'lineStart' | 'lineEnd'>): string {
  return `${f.filePath}:${f.lineStart}${f.lineEnd > f.lineStart ? `–${f.lineEnd}` : ''}`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round((bytes / 1024) * 10) / 10} KB`;
  return `${Math.round((bytes / (1024 * 1024)) * 10) / 10} MB`;
}
