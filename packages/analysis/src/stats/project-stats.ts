import type {
  AnalysisDepth,
  DependencyStats,
  FileRank,
  Language,
  LanguageBreakdown,
  LocCounts,
  OwaspCategory,
  ProjectProfile,
  ProjectStats,
  RiskGrade,
  Severity,
  StatsStage,
  StatsTreeNode,
} from '@webguard/core';
import type { ResolvedDependency } from '../deps/dependencies.js';
import type { InventoryFile, ProjectInventory } from '../profiler/profiler.js';
import { addLoc, emptyLoc } from './loc.js';

/**
 * Project Overview statistics. Built once per scan from what the pipeline already produced
 * (extraction result, the profiler's single-pass inventory, the dependency set, the persisted
 * findings and their rollup), so nothing is re-read or recomputed when the stats are served.
 * Every input past the upload is optional: a scan that failed part-way gets the statistics of
 * the stages it finished (`status: 'partial'`).
 */

export interface StatsFinding {
  filePath: string;
  severity: Severity;
  owaspCategory: string;
  detectorId: string;
  /** One string (raw finding) or the merged list (persisted finding). */
  evidence: string | readonly string[];
  contributingDetectors?: readonly string[];
}

export interface StatsRollup {
  total: number;
  bySeverity: Record<Severity, number>;
  byOwaspCategory: Partial<Record<OwaspCategory, number>>;
  riskScore: number;
  grade: RiskGrade;
  gradeReason: string;
}

/** Unique dependency names from every manifest and lockfile (see collectDependencies). */
export interface DependencyCounts {
  direct: number;
  transitive: number;
  manifests: string[];
}

export interface ExtractionFacts {
  filesExtracted: number;
  totalBytes: number;
  skippedFileCount: number;
  skippedDirs: string[];
  skippedEntries: number;
}

export interface TreeLimits {
  /** Directories deeper than this are shown collapsed (counts only). Root = depth 0. */
  maxDepth: number;
  /** Total nodes serialized (breadth-first, so shallow levels always fit). */
  maxNodes: number;
  /** Children listed per directory; the rest are summarized in `omitted`. */
  maxChildren: number;
}

export const DEFAULT_TREE_LIMITS: TreeLimits = { maxDepth: 8, maxNodes: 1500, maxChildren: 200 };

export interface ProjectStatsInput {
  stage: StatsStage;
  zipBytes: number | null;
  extraction?: ExtractionFacts | null;
  profile?: ProjectProfile | null;
  inventory?: ProjectInventory | null;
  dependencies?: DependencyCounts | null;
  findings?: readonly StatsFinding[] | null;
  rollup?: StatsRollup | null;
  scan: {
    startedAt: Date | null;
    finishedAt: Date | null;
    rules: readonly string[];
    filesParsed?: number | null;
    parseErrors?: number | null;
  };
  treeLimits?: Partial<TreeLimits>;
  now?: Date;
}

const TOP_N = 5;
const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const worse = (a: Severity | null, b: Severity | null): Severity | null =>
  a === null ? b : b === null ? a : SEVERITY_ORDER.indexOf(a) <= SEVERITY_ORDER.indexOf(b) ? a : b;

/** Languages the parser layer turns into an AST (taint/data-flow detectors run on them). */
const AST_LANGUAGES = new Set<Language>(['javascript', 'typescript']);
export function analysisDepthOf(language: Language): { depth: AnalysisDepth; label: string } {
  return AST_LANGUAGES.has(language)
    ? { depth: 'full-ast', label: 'full AST analysis' }
    : { depth: 'pattern-only', label: 'secrets/crypto/deps/config only' };
}

const DEPS_DETECTOR = 'A11-vulnerable-deps';

export function buildProjectStats(input: ProjectStatsInput): ProjectStats {
  const { inventory, profile, extraction } = input;
  const findings = input.findings ?? null;
  const files = inventory?.files ?? null;

  // ---- size ----
  const textFiles = (files ?? []).filter((f) => f.lines !== null);
  const rank = (f: InventoryFile): FileRank => ({
    path: f.path,
    bytes: f.bytes,
    lines: f.lines,
    language: f.language,
  });
  const largestFiles = [...(files ?? [])]
    .sort((a, b) => b.bytes - a.bytes || a.path.localeCompare(b.path))
    .slice(0, TOP_N)
    .map(rank);
  const longestFiles = [...textFiles]
    .sort((a, b) => b.lines! - a.lines! || a.path.localeCompare(b.path))
    .slice(0, TOP_N)
    .map(rank);

  // ---- languages ----
  const byLanguage = new Map<Language, LanguageBreakdown>();
  const totalLoc: LocCounts | null = files ? emptyLoc() : null;
  for (const f of files ?? []) {
    if (f.kind !== 'source' || !f.language) continue;
    let entry = byLanguage.get(f.language);
    if (!entry) {
      const { depth, label } = analysisDepthOf(f.language);
      entry = {
        language: f.language,
        files: 0,
        bytes: 0,
        loc: emptyLoc(),
        analysisDepth: depth,
        analysisLabel: label,
      };
      byLanguage.set(f.language, entry);
    }
    entry.files++;
    entry.bytes += f.bytes;
    if (f.loc) {
      addLoc(entry.loc, f.loc);
      addLoc(totalLoc!, f.loc);
    }
  }
  const languages = [...byLanguage.values()].sort(
    (a, b) =>
      b.loc.total - a.loc.total || b.files - a.files || a.language.localeCompare(b.language),
  );

  // ---- security ----
  const security = findings && input.rollup ? securityOf(findings, input.rollup) : null;

  const unpacked =
    extraction?.totalBytes ?? (files ? files.reduce((sum, f) => sum + f.bytes, 0) : null);
  const durationMs =
    input.scan.startedAt && input.scan.finishedAt
      ? Math.max(0, input.scan.finishedAt.getTime() - input.scan.startedAt.getTime())
      : null;

  return {
    version: 1,
    status: input.stage === 'complete' ? 'complete' : 'partial',
    stage: input.stage,
    computedAt: (input.now ?? new Date()).toISOString(),
    size: {
      files: files ? files.length : (extraction?.filesExtracted ?? null),
      folders: inventory ? inventory.folders.length : null,
      zipBytes: input.zipBytes,
      unpackedBytes: unpacked,
      loc: totalLoc,
      largestFiles,
      longestFiles,
    },
    languages,
    stack:
      profile && inventory
        ? {
            frameworks: profile.frameworks,
            entryPoints: inventory.entryPoints,
            packageManagers: inventory.packageManagers,
          }
        : null,
    tree: inventory
      ? buildTree(inventory, findings ?? [], { ...DEFAULT_TREE_LIMITS, ...input.treeLimits })
      : null,
    dependencies:
      input.dependencies && findings ? dependencyStatsOf(input.dependencies, findings) : null,
    security,
    skipped: {
      ignoredDirFiles:
        (extraction?.skippedFileCount ?? 0) + (profile?.ignored.byReason['ignored-dir'] ?? 0),
      ignoredDirs: extraction?.skippedDirs ?? [],
      binary: profile?.ignored.byReason.binary ?? 0,
      tooLarge: profile?.ignored.byReason['too-large'] ?? 0,
      unrecognized: profile?.ignored.byReason.unrecognized ?? 0,
      unsupportedEntries: extraction?.skippedEntries ?? 0,
    },
    scan: {
      startedAt: input.scan.startedAt?.toISOString() ?? null,
      finishedAt: input.scan.finishedAt?.toISOString() ?? null,
      durationMs,
      rules: [...input.scan.rules],
      filesParsed: input.scan.filesParsed ?? null,
      parseErrors: input.scan.parseErrors ?? null,
    },
  };
}

function securityOf(
  findings: readonly StatsFinding[],
  rollup: StatsRollup,
): NonNullable<ProjectStats['security']> {
  const perFile = new Map<string, { findings: number; worstSeverity: Severity }>();
  for (const f of findings) {
    const entry = perFile.get(f.filePath);
    if (entry) {
      entry.findings++;
      entry.worstSeverity = worse(entry.worstSeverity, f.severity)!;
    } else {
      perFile.set(f.filePath, { findings: 1, worstSeverity: f.severity });
    }
  }
  const topFiles = [...perFile.entries()]
    .map(([path, v]) => ({ path, ...v }))
    .sort(
      (a, b) =>
        b.findings - a.findings ||
        SEVERITY_ORDER.indexOf(a.worstSeverity) - SEVERITY_ORDER.indexOf(b.worstSeverity) ||
        a.path.localeCompare(b.path),
    )
    .slice(0, TOP_N);
  // The rollup's numbers, so the overview, dashboard and reports never disagree.
  return {
    total: rollup.total,
    bySeverity: { ...rollup.bySeverity },
    byOwaspCategory: { ...rollup.byOwaspCategory },
    topFiles,
    riskScore: rollup.riskScore,
    grade: rollup.grade,
    gradeReason: rollup.gradeReason,
  };
}

/** Direct vs transitive unique package names, from collectDependencies() (A11's input). */
export function dependencyCountsOf(
  deps: readonly Pick<ResolvedDependency, 'name' | 'direct' | 'file' | 'declaredFile'>[],
): DependencyCounts {
  const direct = new Set<string>();
  const all = new Set<string>();
  const manifests = new Set<string>();
  for (const d of deps) {
    all.add(d.name);
    if (d.direct) direct.add(d.name);
    manifests.add(d.file);
    if (d.declaredFile) manifests.add(d.declaredFile);
  }
  return { direct: direct.size, transitive: all.size - direct.size, manifests: [...manifests] };
}

const TYPOSQUAT = /^possible typosquat: "([^"]+)".*likely intended package: (\S+)/;
const PACKAGE_AT = /^((?:@[^/\s]+\/)?[^@\s]+)@/;

/** Vulnerable / end-of-life / typosquat counts, read from the A11 findings' evidence. */
export function dependencyStatsOf(
  counts: DependencyCounts,
  findings: readonly StatsFinding[],
): DependencyStats {
  const vulnerable = new Set<string>();
  const outdated = new Set<string>();
  const typosquats = new Map<string, string | null>();
  for (const f of findings) {
    if (f.detectorId !== DEPS_DETECTOR && !f.contributingDetectors?.includes(DEPS_DETECTOR)) {
      continue;
    }
    for (const evidence of typeof f.evidence === 'string' ? [f.evidence] : f.evidence) {
      const squat = TYPOSQUAT.exec(evidence);
      if (squat?.[1]) {
        typosquats.set(squat[1], squat[2] ?? null);
        continue;
      }
      const pkg = PACKAGE_AT.exec(evidence)?.[1];
      if (!pkg) continue;
      if (/\): end-of-life\b/.test(evidence)) outdated.add(pkg);
      else vulnerable.add(pkg);
    }
  }
  return {
    direct: counts.direct,
    transitive: counts.transitive,
    total: counts.direct + counts.transitive,
    vulnerable: vulnerable.size,
    outdated: outdated.size,
    typosquats: [...typosquats.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([name, target]) => ({ name, target })),
    manifests: [...counts.manifests].sort(),
  };
}

// ---------------------------------------------------------------------------
// Folder tree
// ---------------------------------------------------------------------------

interface MutableNode {
  name: string;
  path: string;
  type: 'dir' | 'file';
  files: number;
  findings: number;
  worst: Severity | null;
  language?: Language | null;
  dirs: Map<string, MutableNode>;
  fileChildren: Map<string, MutableNode>;
}

const newNode = (name: string, path: string, type: 'dir' | 'file'): MutableNode => ({
  name,
  path,
  type,
  files: 0,
  findings: 0,
  worst: null,
  dirs: new Map(),
  fileChildren: new Map(),
});

/**
 * The project's folder tree with per-subtree file and finding counts and the worst severity.
 * Counts are exact; only the serialized shape is capped (depth, total nodes, children per
 * directory), breadth-first, with what was left out summarized in `omitted`.
 */
export function buildTree(
  inventory: Pick<ProjectInventory, 'files' | 'folders'>,
  findings: readonly Pick<StatsFinding, 'filePath' | 'severity'>[],
  limits: TreeLimits = DEFAULT_TREE_LIMITS,
): StatsTreeNode {
  const root = newNode('', '', 'dir');
  const dirAt = (dirPath: string): MutableNode => {
    let node = root;
    if (dirPath === '') return node;
    let acc = '';
    for (const seg of dirPath.split('/')) {
      acc = acc ? `${acc}/${seg}` : seg;
      let next = node.dirs.get(seg);
      if (!next) {
        next = newNode(seg, acc, 'dir');
        node.dirs.set(seg, next);
      }
      node = next;
    }
    return node;
  };

  for (const folder of inventory.folders) dirAt(folder);
  for (const f of inventory.files) {
    const slash = f.path.lastIndexOf('/');
    const parent = dirAt(slash < 0 ? '' : f.path.slice(0, slash));
    const name = f.path.slice(slash + 1);
    const node = newNode(name, f.path, 'file');
    node.files = 1;
    node.language = f.language;
    parent.fileChildren.set(name, node);
    // Ancestors' file counts.
    let n = root;
    n.files++;
    for (const seg of slash < 0 ? [] : f.path.slice(0, slash).split('/')) {
      n = n.dirs.get(seg)!;
      n.files++;
    }
  }

  // Each finding counts on every node from the root down to its file (or the deepest node of
  // its path that exists, e.g. a manifest finding in a file that was not extracted).
  for (const f of findings) {
    const segs = f.filePath.split('/');
    let n: MutableNode | undefined = root;
    for (let i = 0; n; i++) {
      n.findings++;
      n.worst = worse(n.worst, f.severity);
      if (i >= segs.length) break;
      const seg = segs[i]!;
      n = i === segs.length - 1 ? (n.fileChildren.get(seg) ?? n.dirs.get(seg)) : n.dirs.get(seg);
    }
  }

  // Breadth-first serialization under the caps.
  const out = toOut(root);
  let budget = limits.maxNodes - 1;
  const queue: Array<{ node: MutableNode; out: StatsTreeNode; depth: number }> = [
    { node: root, out, depth: 0 },
  ];
  while (queue.length > 0) {
    const { node, out: o, depth } = queue.shift()!;
    const children = [
      ...[...node.dirs.values()].sort((a, b) => cmpName(a.name, b.name)),
      ...[...node.fileChildren.values()].sort((a, b) => cmpName(a.name, b.name)),
    ];
    o.children = [];
    const omitted = { dirs: 0, files: 0 };
    for (const child of children) {
      const fits = depth < limits.maxDepth && budget > 0 && o.children.length < limits.maxChildren;
      if (!fits) {
        if (child.type === 'dir') omitted.dirs++;
        else omitted.files++;
        continue;
      }
      budget--;
      const childOut = toOut(child);
      o.children.push(childOut);
      if (child.type === 'dir') queue.push({ node: child, out: childOut, depth: depth + 1 });
    }
    if (omitted.dirs > 0 || omitted.files > 0) o.omitted = omitted;
  }
  return out;
}

const cmpName = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

function toOut(n: MutableNode): StatsTreeNode {
  return {
    name: n.name,
    path: n.path,
    type: n.type,
    files: n.files,
    findings: n.findings,
    worstSeverity: n.worst,
    ...(n.type === 'file' ? { language: n.language ?? null } : {}),
  };
}
