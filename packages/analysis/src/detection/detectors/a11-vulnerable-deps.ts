import { SnapshotAdvisorySource, type AdvisorySource } from '../../deps/advisories.js';
import {
  collectDependencies,
  editDistance,
  type ResolvedDependency,
} from '../../deps/dependencies.js';
import { POPULAR_PACKAGES, TYPOSQUAT_ALLOWLIST } from '../../deps/popular-packages.js';
import { registerDetector } from '../registry.js';
import type { Detector, RawFinding } from '../types.js';

/**
 * A11 — Vulnerable & typosquatted dependencies (dependency).
 *
 *  1. Vulnerable / EOL: every resolved dependency (direct + transitive, from package.json and
 *     package-lock / yarn / pnpm lockfiles) is checked against the configured AdvisorySources.
 *     Default: the bundled offline snapshot only, with no network. A live `OsvAdvisorySource`
 *     can be added when outbound access is allowed. Lockfile versions are exact (confidence
 *     0.9); a package.json range is checked at its minimum version (0.7). Juice Shop #31
 *     (sanitize-html 1.4.2).
 *  2. Typosquatting: a dependency 1–2 edits away from a popular package (or equal to one
 *     after stripping a `-js` / `node-` style affix) that is not itself popular or on the
 *     verified allowlist. Juice Shop #32 (epilogue-js vs epilogue, ngy-cookie vs ngx-cookie).
 */

const CATEGORY = 'A03:2025-Software Supply Chain Failures' as const;
const POPULAR = new Set(POPULAR_PACKAGES);
const AFFIX = /^(node-|js-)|(-js|\.js|-node|js|-npm)$/;

export interface DependencyDetectorOptions {
  sources?: AdvisorySource[];
}

function typosquatTarget(
  name: string,
): { target: string; how: string; confidence: number } | undefined {
  if (
    POPULAR.has(name) ||
    TYPOSQUAT_ALLOWLIST.has(name) ||
    name.startsWith('@') ||
    name.startsWith('@types/')
  )
    return undefined;
  const stripped = name.replace(AFFIX, '');
  if (stripped !== name && POPULAR.has(stripped)) {
    return {
      target: stripped,
      how: `"${stripped}" plus a "${name.replace(stripped, '')}" affix`,
      confidence: 0.6,
    };
  }
  if (name.length < 5) return undefined; // short names collide too often
  let best: { target: string; d: number } | undefined;
  for (const p of POPULAR_PACKAGES) {
    if (p.startsWith('@')) continue;
    const d = editDistance(name, p, 2);
    if (d >= 1 && d <= 2 && (!best || d < best.d)) best = { target: p, d };
  }
  if (!best) return undefined;
  return {
    target: best.target,
    how: `${best.d} edit${best.d > 1 ? 's' : ''} from "${best.target}"`,
    confidence: best.d === 1 ? 0.65 : 0.5,
  };
}

export function createDependencyDetector(options: DependencyDetectorOptions = {}): Detector {
  const sources = options.sources ?? [new SnapshotAdvisorySource()];
  return {
    id: 'A11-vulnerable-deps',
    title: 'Vulnerable or typosquatted dependency',
    owaspCategory: CATEGORY,
    cwe: 'CWE-1395',
    technique: 'dependency',
    explanation:
      'The project depends on a package version with a published vulnerability (or one that ' +
      'is end-of-life and no longer patched). Attackers scan for known-vulnerable versions; ' +
      'the advisory describes what they can do with it.',
    fixSuggestion:
      'Upgrade to the fixed version (npm install <pkg>@<fixed>) or replace the package, then re-run the scan.',

    async run(ctx) {
      const deps = collectDependencies(ctx);
      const findings: RawFinding[] = [];

      // One lookup per unique name@version; report at its best location (lockfile first).
      const byKey = new Map<string, ResolvedDependency>();
      for (const d of deps) {
        const key = `${d.name}@${d.version}`;
        const prev = byKey.get(key);
        if (!prev || (d.resolved && !prev.resolved) || (d.direct && !prev.direct))
          byKey.set(key, d);
      }
      const unique = [...byKey.values()];
      const refs = unique.map((d) => ({ name: d.name, version: d.version }));

      for (const source of sources) {
        const { matches } = await source.lookup(refs);
        for (const { advisory, pkg } of matches) {
          const dep = byKey.get(`${pkg.name}@${pkg.version}`);
          if (!dep) continue;
          const versionNote = dep.resolved
            ? pkg.version
            : `${pkg.version} (minimum of "${dep.declaredRange}"; resolved version unknown)`;
          const where = dep.direct ? 'direct dependency' : 'transitive dependency';
          const eol = advisory.kind === 'eol';
          findings.push({
            detectorId: 'A11-vulnerable-deps',
            owaspCategory: CATEGORY,
            severity: advisory.severity,
            confidence: eol ? 0.8 : dep.resolved ? 0.9 : 0.7,
            filePath: dep.declaredFile ?? dep.file,
            lineStart: dep.declaredLine ?? dep.line,
            lineEnd: dep.declaredLine ?? dep.line,
            snippet: ctx.snippet(dep.declaredFile ?? dep.file, dep.declaredLine ?? dep.line),
            evidence:
              `${pkg.name}@${versionNote} (${where}): ${eol ? 'end-of-life' : advisory.id}${advisory.aliases?.length ? ` / ${advisory.aliases.join(', ')}` : ''}: ${advisory.summary}` +
              (advisory.fixedVersion ? ` Fixed in ${advisory.fixedVersion}.` : '') +
              ` [source: ${source.id}]`,
            explanation: eol
              ? `${pkg.name} is end-of-life/unmaintained: future vulnerabilities will not be fixed. ${advisory.summary}`
              : undefined,
            fixSuggestion: advisory.fixedVersion
              ? `Upgrade ${pkg.name} to ${advisory.fixedVersion} or later (npm install ${pkg.name}@^${advisory.fixedVersion}).`
              : eol
                ? `Replace ${pkg.name} with a maintained alternative.`
                : undefined,
            cwe: eol ? 'CWE-1104' : 'CWE-1395',
          });
        }
      }

      // ---- Typosquatting (direct dependencies only: that's what someone typed) ----
      const seen = new Set<string>();
      for (const dep of deps) {
        if (!dep.direct || seen.has(dep.name)) continue;
        seen.add(dep.name);
        const squat = typosquatTarget(dep.name);
        if (!squat) continue;
        const declared = { file: dep.declaredFile ?? dep.file, line: dep.declaredLine ?? dep.line };
        findings.push({
          detectorId: 'A11-vulnerable-deps',
          owaspCategory: CATEGORY,
          severity: 'high',
          confidence: squat.confidence,
          filePath: declared.file,
          lineStart: declared.line,
          lineEnd: declared.line,
          snippet: ctx.snippet(declared.file, declared.line),
          evidence: `possible typosquat: "${dep.name}" is ${squat.how}; likely intended package: ${squat.target}`,
          explanation:
            'This dependency name is suspiciously close to a popular package. Typosquatted ' +
            'packages copy a well-known name to get installed by mistake, then run malicious ' +
            'install scripts or ship backdoored code. Confirm the package is the one you meant.',
          fixSuggestion: `Verify the package on the registry; if unintended, replace it with "${squat.target}" and audit what the impostor ran (install scripts, network access).`,
          cwe: 'CWE-1357',
        });
      }
      return findings;
    },
  };
}

export const vulnerableDependencies = registerDetector(createDependencyDetector());
