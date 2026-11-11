import type { Advisory } from './advisories.js';

/**
 * Bundled offline advisory snapshot.
 *
 * A small, curated sample covering the packages the documented challenges rely on and a few
 * well-known npm vulnerabilities, so the dependency detector works with no network access.
 * It is NOT a complete database: verify details against OSV / GitHub Advisories before
 * relying on them, and plug in a live source (see OsvAdvisorySource) for real coverage.
 */
export const SNAPSHOT_META = {
  name: 'webguard-bundled-sample',
  note: 'Curated offline sample for offline scans and tests; verify against OSV before relying on it.',
} as const;

export const ADVISORY_SNAPSHOT: Advisory[] = [
  {
    id: 'CVE-2016-1000237',
    package: 'sanitize-html',
    vulnerableRange: '<1.4.3',
    fixedVersion: '1.4.3',
    severity: 'high',
    kind: 'vulnerability',
    summary: 'Cross-site scripting: crafted nested markup bypasses sanitization.',
  },
  {
    id: 'CVE-2020-15084',
    aliases: ['GHSA-6g6m-m6h5-w9gf'],
    package: 'express-jwt',
    vulnerableRange: '<6.0.0',
    fixedVersion: '6.0.0',
    severity: 'high',
    kind: 'vulnerability',
    summary: 'Authorization bypass when the `algorithms` option is not specified.',
  },
  {
    id: 'CVE-2022-23540',
    package: 'jsonwebtoken',
    vulnerableRange: '<9.0.0',
    fixedVersion: '9.0.0',
    severity: 'high',
    kind: 'vulnerability',
    summary: 'Insecure default algorithm handling allows signature validation bypass.',
  },
  {
    id: 'CVE-2021-23337',
    package: 'lodash',
    vulnerableRange: '<4.17.21',
    fixedVersion: '4.17.21',
    severity: 'high',
    kind: 'vulnerability',
    summary: 'Command injection via the template function.',
  },
  {
    id: 'CVE-2021-44906',
    package: 'minimist',
    vulnerableRange: '<1.2.6',
    fixedVersion: '1.2.6',
    severity: 'critical',
    kind: 'vulnerability',
    summary: 'Prototype pollution.',
  },
  {
    id: 'CVE-2022-24785',
    package: 'moment',
    vulnerableRange: '<2.29.2',
    fixedVersion: '2.29.2',
    severity: 'high',
    kind: 'vulnerability',
    summary: 'Path traversal in locale loading.',
  },
  {
    id: 'EOL-request',
    package: 'request',
    vulnerableRange: '*',
    severity: 'medium',
    kind: 'eol',
    summary: 'Deprecated by its maintainers (February 2020); receives no security fixes.',
  },
  {
    id: 'EOL-marsdb',
    package: 'marsdb',
    vulnerableRange: '*',
    severity: 'medium',
    kind: 'eol',
    summary: 'Unmaintained (no releases for years); per this snapshot, treat as end-of-life.',
  },
];
