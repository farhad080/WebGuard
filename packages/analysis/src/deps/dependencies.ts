import path from 'node:path';
import semver from 'semver';
import type { DetectionContext } from '../detection/types.js';

/** One resolved dependency occurrence, with where it was found (for report locations). */
export interface ResolvedDependency {
  name: string;
  version: string;
  /** True when declared in a package.json (vs. only transitive in a lockfile). */
  direct: boolean;
  /** Version came from a lockfile (exact) rather than a package.json range. */
  resolved: boolean;
  file: string;
  line: number;
  /** The package.json range, when declared directly. */
  declaredRange?: string;
  /** Where it is declared in a package.json (for direct dependencies). */
  declaredFile?: string;
  declaredLine?: number;
}

function lineOf(text: string, needle: string | RegExp): number {
  const lines = text.split('\n');
  const i = lines.findIndex((l) =>
    typeof needle === 'string' ? l.includes(needle) : needle.test(l),
  );
  return i >= 0 ? i + 1 : 1;
}

function fromPackageJson(file: string, text: string): ResolvedDependency[] {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return [];
  }
  const out: ResolvedDependency[] = [];
  for (const field of [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
  ]) {
    const deps = pkg[field];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, range] of Object.entries(deps as Record<string, string>)) {
      if (typeof range !== 'string') continue;
      // `^1.4.2` → 1.4.2: the lowest version the range allows (unknown exact install).
      const min = semver.validRange(range) ? semver.minVersion(range)?.version : undefined;
      out.push({
        name,
        version: min ?? range,
        direct: true,
        resolved: false,
        file,
        line: lineOf(text, `"${name}"`),
        declaredRange: range,
      });
    }
  }
  return out;
}

/** package-lock.json v1 (nested `dependencies`) and v2/v3 (`packages` map). */
function fromPackageLock(file: string, text: string): ResolvedDependency[] {
  let lock: {
    packages?: Record<string, { version?: string }>;
    dependencies?: Record<string, unknown>;
  };
  try {
    lock = JSON.parse(text);
  } catch {
    return [];
  }
  const out: ResolvedDependency[] = [];
  if (lock.packages) {
    for (const [key, info] of Object.entries(lock.packages)) {
      if (!key.includes('node_modules/') || !info?.version) continue;
      const name = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      out.push({
        name,
        version: info.version,
        direct: false,
        resolved: true,
        file,
        line: lineOf(text, `"${key}"`),
      });
    }
  } else if (lock.dependencies) {
    const walk = (deps: Record<string, unknown>) => {
      for (const [name, info] of Object.entries(deps)) {
        const entry = info as { version?: string; dependencies?: Record<string, unknown> };
        if (entry.version) {
          out.push({
            name,
            version: entry.version,
            direct: false,
            resolved: true,
            file,
            line: lineOf(text, `"${name}": {`),
          });
        }
        if (entry.dependencies) walk(entry.dependencies);
      }
    };
    walk(lock.dependencies);
  }
  return out;
}

/** yarn.lock v1: `"name@^1.0.0", name@~1.0.1:` followed by `  version "1.0.3"`. */
function fromYarnLock(file: string, text: string): ResolvedDependency[] {
  const out: ResolvedDependency[] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const header = /^"?((?:@[^@/\s"]+\/)?[^@\s"]+)@[^:]*:\s*$/.exec(lines[i] ?? '');
    if (!header?.[1]) continue;
    for (let j = i + 1; j < Math.min(i + 6, lines.length); j++) {
      const v = /^\s+version:?\s+"?([^"\s]+)"?/.exec(lines[j] ?? '');
      if (v?.[1]) {
        out.push({
          name: header[1],
          version: v[1],
          direct: false,
          resolved: true,
          file,
          line: i + 1,
        });
        break;
      }
    }
  }
  return out;
}

/** pnpm-lock.yaml: `/name@1.2.3:` (v6+) or `/name/1.2.3:` (older). */
function fromPnpmLock(file: string, text: string): ResolvedDependency[] {
  const out: ResolvedDependency[] = [];
  text.split('\n').forEach((line, i) => {
    const m = /^\s+'?\/((?:@[^/@]+\/)?[^/@:]+)[@/](\d[^:('"]*)/.exec(line);
    if (m?.[1] && m[2])
      out.push({ name: m[1], version: m[2], direct: false, resolved: true, file, line: i + 1 });
  });
  return out;
}

/**
 * The project's dependency set (direct + transitive), from every package.json and lockfile.
 * Lockfile versions take precedence (exact); package.json ranges fall back to their minimum.
 */
export function collectDependencies(ctx: DetectionContext): ResolvedDependency[] {
  const all: ResolvedDependency[] = [];
  for (const manifest of ctx.manifests) {
    if (manifest.path.split('/').includes('node_modules')) continue;
    const text = ctx.readText(manifest.path);
    if (text === null) continue;
    const base = path.posix.basename(manifest.path);
    if (base === 'package.json') all.push(...fromPackageJson(manifest.path, text));
    else if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json')
      all.push(...fromPackageLock(manifest.path, text));
    else if (base === 'yarn.lock') all.push(...fromYarnLock(manifest.path, text));
    else if (base === 'pnpm-lock.yaml') all.push(...fromPnpmLock(manifest.path, text));
  }

  // Merge: a lockfile entry for a directly declared package becomes "direct + resolved".
  const declarations = new Map(all.filter((d) => d.direct).map((d) => [d.name, d] as const));
  const lockedNames = new Set(
    all.filter((d) => d.resolved).map((d) => `${path.posix.dirname(d.file)}\u0000${d.name}`),
  );
  return all
    .filter((d) => d.resolved || !lockedNames.has(`${path.posix.dirname(d.file)}\u0000${d.name}`))
    .map((d) => {
      const decl = declarations.get(d.name);
      if (!decl) return d;
      return {
        ...d,
        direct: true,
        declaredRange: decl.declaredRange,
        declaredFile: decl.file,
        declaredLine: decl.line,
      };
    });
}

/** Levenshtein distance (small strings; early exit above `max`). */
export function editDistance(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const v = Math.min(
        prev[j]! + 1,
        cur[j - 1]! + 1,
        prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      cur.push(v);
      rowMin = Math.min(rowMin, v);
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length]!;
}
