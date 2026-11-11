import type { Severity } from '@webguard/core';
import semver from 'semver';
import { ADVISORY_SNAPSHOT, SNAPSHOT_META } from './advisory-snapshot.js';

export interface PackageRef {
  name: string;
  version: string;
}

export interface Advisory {
  /** CVE / GHSA / OSV id, or a synthetic `EOL-<name>` id for end-of-life notices. */
  id: string;
  aliases?: string[];
  package: string;
  /** semver range of affected versions (`*` = all). */
  vulnerableRange: string;
  fixedVersion?: string;
  severity: Severity;
  kind: 'vulnerability' | 'eol' | 'malicious';
  summary: string;
}

export interface AdvisoryMatch {
  advisory: Advisory;
  pkg: PackageRef;
}

export interface AdvisoryResult {
  matches: AdvisoryMatch[];
  /** Non-fatal problems, e.g. "network access disabled". */
  warnings: string[];
}

/**
 * Where vulnerability data comes from. Implementations: the bundled offline snapshot (default)
 * and an OSV client that is only active when network access is explicitly allowed.
 */
export interface AdvisorySource {
  readonly id: string;
  lookup(packages: readonly PackageRef[]): Promise<AdvisoryResult>;
}

function affects(range: string, version: string): boolean {
  if (range === '*') return true;
  const v = semver.valid(version) ?? semver.valid(semver.coerce(version));
  return v !== null && semver.satisfies(v, range, { includePrerelease: true });
}

/** Offline: matches packages against a bundled advisory list. Never touches the network. */
export class SnapshotAdvisorySource implements AdvisorySource {
  readonly id: string;
  private readonly byName = new Map<string, Advisory[]>();

  constructor(
    advisories: readonly Advisory[] = ADVISORY_SNAPSHOT,
    id: string = SNAPSHOT_META.name,
  ) {
    this.id = id;
    for (const a of advisories) {
      const list = this.byName.get(a.package) ?? [];
      list.push(a);
      this.byName.set(a.package, list);
    }
  }

  async lookup(packages: readonly PackageRef[]): Promise<AdvisoryResult> {
    const matches: AdvisoryMatch[] = [];
    for (const pkg of packages) {
      for (const advisory of this.byName.get(pkg.name) ?? []) {
        if (affects(advisory.vulnerableRange, pkg.version)) matches.push({ advisory, pkg });
      }
    }
    return { matches, warnings: [] };
  }
}

export interface OsvSourceOptions {
  /** Must be explicitly true: scans must not assume outbound network access. */
  allowNetwork?: boolean;
  /** Injected fetch (e.g. globalThis.fetch, or a proxy-aware client). Required when enabled. */
  fetch?: (
    url: string,
    init: { method: string; headers: Record<string, string>; body: string },
  ) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;
  endpoint?: string;
}

interface OsvBatchResponse {
  results?: Array<{ vulns?: Array<{ id: string }> }>;
}

/**
 * Live OSV.dev source (stub, ready to wire in). Disabled unless `allowNetwork` is set and a
 * `fetch` is provided, so the default scan stays fully offline. Uses the batch query API;
 * severity/fixed-version enrichment (GET /v1/vulns/{id}) is left for a later step, so matches
 * are reported as `high` with no fixed version.
 */
export class OsvAdvisorySource implements AdvisorySource {
  readonly id = 'osv';

  constructor(private readonly options: OsvSourceOptions = {}) {}

  async lookup(packages: readonly PackageRef[]): Promise<AdvisoryResult> {
    const { allowNetwork, fetch } = this.options;
    if (!allowNetwork || !fetch) {
      return {
        matches: [],
        warnings: ['OSV lookup skipped: network access is disabled for this scan'],
      };
    }
    const endpoint = this.options.endpoint ?? 'https://api.osv.dev/v1/querybatch';
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          queries: packages.map((p) => ({
            package: { name: p.name, ecosystem: 'npm' },
            version: p.version,
          })),
        }),
      });
      if (!response.ok)
        return { matches: [], warnings: [`OSV lookup failed: HTTP ${response.status}`] };
      const body = (await response.json()) as OsvBatchResponse;
      const matches: AdvisoryMatch[] = [];
      (body.results ?? []).forEach((result, i) => {
        const pkg = packages[i];
        if (!pkg) return;
        for (const vuln of result.vulns ?? []) {
          matches.push({
            pkg,
            advisory: {
              id: vuln.id,
              package: pkg.name,
              vulnerableRange: pkg.version,
              severity: 'high',
              kind: 'vulnerability',
              summary: `Reported by OSV (${vuln.id}); see https://osv.dev/vulnerability/${vuln.id}`,
            },
          });
        }
      });
      return { matches, warnings: [] };
    } catch (err) {
      return { matches: [], warnings: [`OSV lookup failed: ${(err as Error).message}`] };
    }
  }
}
