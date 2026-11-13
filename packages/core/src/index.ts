/** ISO-8601 timestamp string as serialized over the API. */
export type IsoDateString = string;

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** OWASP Top 10:2025 categories (https://owasp.org/Top10/2025/). */
export type OwaspCategory =
  | 'A01:2025-Broken Access Control'
  | 'A02:2025-Security Misconfiguration'
  | 'A03:2025-Software Supply Chain Failures'
  | 'A04:2025-Cryptographic Failures'
  | 'A05:2025-Injection'
  | 'A06:2025-Insecure Design'
  | 'A07:2025-Authentication Failures'
  | 'A08:2025-Software or Data Integrity Failures'
  | 'A09:2025-Logging and Alerting Failures'
  | 'A10:2025-Mishandling of Exceptional Conditions';

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';

export type ArtifactKind = 'raw_zip' | 'extracted' | 'report';

export interface Project {
  id: string;
  userId: string;
  name: string;
  createdAt: IsoDateString;
}

/** Compact view of a project's most recent scan (for project cards). */
export interface LastScanSummary {
  id: string;
  status: ScanStatus;
  createdAt: IsoDateString;
  finishedAt: IsoDateString | null;
  /** Present once the scan completed. */
  rollup: ScanRollup | null;
}

export interface ProjectWithLastScan extends Project {
  lastScan: LastScanSummary | null;
}

// ---------------------------------------------------------------------------
// Project profile (produced by the profiler, stored in scan summary_json.profile)
// ---------------------------------------------------------------------------

export type Language =
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'php'
  | 'ruby'
  | 'java'
  | 'go'
  | 'csharp'
  | 'html'
  | 'css'
  | 'vue'
  | 'svelte'
  | 'json'
  | 'yaml'
  | 'toml'
  | 'xml'
  | 'sql'
  | 'shell'
  | 'dockerfile'
  | 'terraform'
  | 'markdown';

export interface LanguageStat {
  language: Language;
  files: number;
  bytes: number;
}

export type FrameworkKind = 'runtime' | 'framework';

export interface DetectedFramework {
  /** e.g. "Node.js", "Express", "React", "Angular". */
  name: string;
  kind: FrameworkKind;
  /** Manifest that revealed it, e.g. "package.json" or "api/package.json". */
  evidence: string;
}

export type ManifestKind = 'manifest' | 'lockfile';

export interface ManifestFile {
  path: string;
  /** Basename, e.g. "package.json", "yarn.lock". */
  type: string;
  kind: ManifestKind;
}

export type SensitivePathCategory =
  | 'env'
  | 'dockerfile'
  | 'compose'
  | 'terraform'
  | 'infra-config'
  | 'key-material'
  | 'static-served';

export interface SensitivePath {
  path: string;
  category: SensitivePathCategory;
}

export interface SourceFile {
  path: string;
  language: Language;
  bytes: number;
}

export type IgnoreReason = 'ignored-dir' | 'binary' | 'too-large' | 'unrecognized';

export interface ProjectProfile {
  /** Sorted by file count, descending. */
  languages: LanguageStat[];
  frameworks: DetectedFramework[];
  manifests: ManifestFile[];
  sensitivePaths: SensitivePath[];
  /** Files the analysis stages should read. All paths are `/`-separated and project-relative. */
  sourceFiles: SourceFile[];
  ignored: { total: number; byReason: Record<IgnoreReason, number> };
  totals: { files: number; bytes: number };
}

/**
 * A documented challenge/weakness class that source analysis cannot detect reliably
 * (policy, runtime behaviour, discovery). Shown as informational instead of being dropped.
 */
export interface InformationalNote {
  id: string;
  title: string;
  /** Related reference(s), e.g. Juice Shop challenge numbers. */
  references: string[];
  /** Why it isn't detected from source, and how to check it instead. */
  note: string;
}

export interface DetectorErrorInfo {
  detectorId: string;
  message: string;
}

export interface ParseErrorSample {
  path: string;
  message: string;
  line?: number;
  column?: number;
}

/** Written by the worker. Detector results are a placeholder until detection exists. */
export type RiskGrade = 'A' | 'B' | 'C' | 'D' | 'F';

/** Per-scan severity/OWASP rollup and risk grade, computed from the persisted findings. */
export interface ScanRollup {
  total: number;
  bySeverity: Record<Severity, number>;
  byOwaspCategory: Partial<Record<OwaspCategory, number>>;
  /** 0 (no risk found) – 100 (severe). See `RISK_MODEL` in the API for the weighting. */
  riskScore: number;
  grade: RiskGrade;
  /** Σ severityWeight × confidence over all findings (the input to riskScore). */
  weightedRisk: number;
  /** Why the grade is what it is, e.g. "capped at D: 3 high-confidence critical findings". */
  gradeReason: string;
  computedAt: IsoDateString;
}

export interface ScanReport {
  reportVersion: 1;
  generatedAt: IsoDateString;
  project: { id: string; name: string };
  scan: {
    id: string;
    status: ScanStatus;
    createdAt: IsoDateString;
    startedAt: IsoDateString | null;
    finishedAt: IsoDateString | null;
  };
  profile: {
    languages: LanguageStat[];
    frameworks: DetectedFramework[];
    sourceFiles: number;
    filesParsed: number;
    parseErrors: number;
    /** Dependency/build/VCS files skipped during extraction (0 for older scans). */
    skippedFileCount: number;
    /** The top-most skipped directories (capped list). */
    skippedDirs: string[];
  } | null;
  rollup: ScanRollup;
  /** Every finding with its remediation, most severe first. */
  findings: Finding[];
  /** Non-code-defect items to review manually (shown, not dropped). */
  informationalNotes: InformationalNote[];
  detectors: string[];
  detectorErrors: DetectorErrorInfo[];
}

export interface ScanSummary {
  filesExtracted?: number;
  totalBytes?: number;
  /** Symlinks, special files, and encrypted entries that were not extracted. */
  skippedEntries?: number;
  /** Files written to disk by the extractor (same as filesExtracted). */
  extractedFiles?: number;
  /** Top-most ignored directories (dependency/build/VCS) that were not extracted, sorted; capped. */
  skippedDirs?: string[];
  /** Files under those directories that were skipped (not extracted, not counted against caps). */
  skippedFileCount?: number;
  profile?: ProjectProfile;
  /** Source files that produced an AST (including ones parsed with recovered errors). */
  filesParsed?: number;
  /** Source files that had a parse error (fatal or recovered). */
  parseErrors?: number;
  /** First few parse errors, for display. */
  parseErrorSamples?: ParseErrorSample[];
  /** Ids of the detectors that ran, in execution order. */
  detectors?: string[];
  /** Counts of the persisted (de-duplicated) findings. */
  findingsTotal?: number;
  findingsBySeverity?: Record<Severity, number>;
  findingsByOwaspCategory?: Partial<Record<OwaspCategory, number>>;
  /** Detectors that threw or returned invalid findings. Non-fatal. */
  detectorErrors?: DetectorErrorInfo[];
  /** Weakness classes that need manual/dynamic review (not findings). */
  informationalNotes?: InformationalNote[];
  /** Authoritative rollup computed from the persisted findings (dashboard + reports). */
  rollup?: ScanRollup;
  /** Present when status is `failed`. */
  error?: string;
}

export interface Scan {
  id: string;
  projectId: string;
  status: ScanStatus;
  startedAt: IsoDateString | null;
  finishedAt: IsoDateString | null;
  summary: ScanSummary | null;
  createdAt: IsoDateString;
}

export interface Finding {
  id: string;
  scanId: string;
  detectorId: string;
  owaspCategory: OwaspCategory;
  severity: Severity;
  /** Detector confidence, 0–1. */
  confidence: number;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  snippet: string;
  explanation: string;
  fixSuggestion: string;
  /**
   * Every detector that reported this issue. When more than one detector flagged the same
   * line and category, the findings are correlated into one; `detectorId` is the primary.
   */
  contributingDetectors: string[];
  /** Short, human-readable reasons from each contributing detector. */
  evidence: string[];
  /** Weakness id of the primary detector's finding, e.g. "CWE-89". */
  cwe: string | null;
  /** Developer-ready fix (null only for rows written before the remediation engine). */
  remediation: Remediation | null;
  createdAt: IsoDateString;
}

/** One side of a scan comparison. */
export interface ScanRef {
  id: string;
  createdAt: IsoDateString;
  finishedAt: IsoDateString | null;
  rollup: ScanRollup | null;
}

/**
 * GET /api/scans/:id/compare?against=:baselineId — how `scan` differs from `against`.
 * Findings are matched by a stable fingerprint (detector + file + normalized code), so a
 * finding that only moved lines still counts as persisting.
 */
export interface ScanComparison {
  scan: ScanRef;
  against: ScanRef;
  /** In the baseline, gone now. */
  fixed: Finding[];
  /** Not in the baseline. */
  new: Finding[];
  /** Still open: the current finding and its baseline counterpart. */
  persisting: { finding: Finding; previous: Finding }[];
  summary: {
    fixed: number;
    new: number;
    persisting: number;
    /** Current minus baseline (negative = fewer findings / less risk). */
    totalDelta: number;
    riskScoreDelta: number | null;
  };
}

export interface RemediationReference {
  title: string;
  url: string;
}

export interface SecureExample {
  language: string;
  /** The vulnerable code; the finding's real snippet when contextualized. */
  before: string;
  /** The secure replacement. */
  after: string;
  /** True when `after` was rewritten from the finding's own code (not the generic template). */
  contextualized: boolean;
  /** Caveats for the rewrite (e.g. "verify the field list"). */
  note?: string;
}

export interface Remediation {
  /** Template id, e.g. "A1-sql-injection" or "A6-weak-crypto/password". */
  templateId: string;
  title: string;
  /** Why the code is vulnerable and how it is exploited. */
  why: string;
  /** What an attacker gains. */
  impact: string;
  /** Numbered remediation algorithm, in order. */
  steps: string[];
  secureExample: SecureExample;
  references: RemediationReference[];
  /** How the secure example was produced. */
  generatedBy: 'template' | 'template+context' | 'llm';
}

export interface Artifact {
  id: string;
  scanId: string;
  kind: ArtifactKind;
  storageKey: string;
  createdAt: IsoDateString;
}

// ---------------------------------------------------------------------------
// File viewer (GET /api/scans/:id/file)
// ---------------------------------------------------------------------------

/** One file of a scan's extracted copy, as returned by GET /api/scans/:id/file. */
export interface ScanFile {
  /** The requested `/`-separated path, relative to the project root. */
  path: string;
  /** Detected from the extension (or shebang); null when unknown. */
  language: Language | null;
  /** Full size of the file on disk, in bytes. */
  size: number;
  /** Lines in `content` (0 for a binary file). */
  lineCount: number;
  /** UTF-8 text with secret lines redacted; '' for a binary file. */
  content: string;
  /** True when the file exceeds MAX_VIEW_FILE_KB and `content` is only its head. */
  truncated: boolean;
  /** True when the file is not text; `content` is then empty. */
  binary: boolean;
  /** Bytes returned at most (MAX_VIEW_FILE_KB). */
  maxBytes: number;
}

/** Why GET /api/scans/:id/file answered 404 (in the `reason` field of the error body). */
export type ScanFileMissingReason =
  /** The path lies in a dependency/build/VCS directory that extraction skips. */
  | 'ignored_dir'
  /** The scan's extracted copy no longer exists (deleted, or the scan failed). */
  | 'extracted_unavailable'
  /** The scan has not been extracted yet (still queued or running). */
  | 'not_ready'
  /** No such file in the extracted copy. */
  | 'not_found';

// ---------------------------------------------------------------------------
// Project Overview statistics (scans.stats_json, GET /api/scans/:id/stats)
// ---------------------------------------------------------------------------

/** Lines of code split by kind (a line-based heuristic per language). */
export interface LocCounts {
  code: number;
  comment: number;
  blank: number;
  /** code + comment + blank. */
  total: number;
}

/** How deeply the detectors analyze a language. */
export type AnalysisDepth = 'full-ast' | 'pattern-only';

export interface LanguageBreakdown {
  language: Language;
  files: number;
  bytes: number;
  loc: LocCounts;
  analysisDepth: AnalysisDepth;
  /** "full AST analysis" or "secrets/crypto/deps/config only". */
  analysisLabel: string;
}

export interface FileRank {
  path: string;
  bytes: number;
  /** Line count; null for a binary file or one over the analysis size limit (not read). */
  lines: number | null;
  language: Language | null;
}

/** One node of the (capped) folder tree. Counts cover the whole subtree, capped or not. */
export interface StatsTreeNode {
  /** Basename ('' for the project root). */
  name: string;
  /** `/`-separated project-relative path ('' for the root). */
  path: string;
  type: 'dir' | 'file';
  /** Files in this subtree (1 for a file). */
  files: number;
  /** Findings in this subtree. */
  findings: number;
  /** Most severe finding in this subtree; null when there are none. */
  worstSeverity: Severity | null;
  /** Only for files. */
  language?: Language | null;
  /** Only for directories: children shown (directories first, then files, by name). */
  children?: StatsTreeNode[];
  /** Only for directories: children left out by the depth/size caps. */
  omitted?: { dirs: number; files: number };
}

export interface PackageManagerInfo {
  /** e.g. "npm", "yarn", "pnpm", "pipenv", "poetry", "composer", "bundler", "go modules". */
  name: string;
  /** The lockfile that revealed it; null when inferred from a manifest without a lockfile. */
  lockfile: string | null;
}

export interface DependencyStats {
  /** Unique package names declared in a manifest (package.json). */
  direct: number;
  /** Unique package names that appear only in a lockfile. */
  transitive: number;
  total: number;
  /** Unique packages with a known vulnerability (A11). */
  vulnerable: number;
  /** Unique packages flagged end-of-life / unmaintained (A11). */
  outdated: number;
  /** Suspected typosquats (A11), with the package they imitate when known. */
  typosquats: Array<{ name: string; target: string | null }>;
  /** Manifests and lockfiles the counts come from. */
  manifests: string[];
}

export interface SkippedStats {
  /** Files in ignored dependency/build/VCS directories (never extracted or analyzed). */
  ignoredDirFiles: number;
  /** The top-most ignored directories (capped list). */
  ignoredDirs: string[];
  /** Binary files (images, fonts, archives, …): kept but not analyzed. */
  binary: number;
  /** Files larger than ANALYSIS_MAX_FILE_BYTES: kept but not analyzed. */
  tooLarge: number;
  /** Text files in a format no detector reads (e.g. LICENSE, .txt). */
  unrecognized: number;
  /** Symlinks, special and encrypted archive entries: never extracted. */
  unsupportedEntries: number;
}

export type StatsStage = 'upload' | 'extraction' | 'analysis' | 'complete';

export interface ProjectStats {
  version: 1;
  /** 'partial' when the scan failed: only the stages that finished are filled in. */
  status: 'complete' | 'partial';
  /** The last pipeline stage whose statistics are included. */
  stage: StatsStage;
  computedAt: IsoDateString;
  size: {
    /** Extracted files (outside ignored directories). */
    files: number | null;
    folders: number | null;
    zipBytes: number | null;
    unpackedBytes: number | null;
    /** Lines of code over every file in a recognized language. */
    loc: LocCounts | null;
    /** Top 5 by bytes. */
    largestFiles: FileRank[];
    /** Top 5 by lines. */
    longestFiles: FileRank[];
  };
  /** By lines, descending. */
  languages: LanguageBreakdown[];
  stack: {
    frameworks: DetectedFramework[];
    /** Most likely first. */
    entryPoints: string[];
    packageManagers: PackageManagerInfo[];
  } | null;
  tree: StatsTreeNode | null;
  dependencies: DependencyStats | null;
  security: {
    total: number;
    bySeverity: Record<Severity, number>;
    byOwaspCategory: Partial<Record<OwaspCategory, number>>;
    /** Top 5 files by finding count. */
    topFiles: Array<{ path: string; findings: number; worstSeverity: Severity }>;
    /** The scan rollup's numbers (same as the dashboard and reports). */
    riskScore: number;
    grade: RiskGrade;
    gradeReason: string;
  } | null;
  skipped: SkippedStats;
  scan: {
    startedAt: IsoDateString | null;
    finishedAt: IsoDateString | null;
    durationMs: number | null;
    /** Detector rules that ran, in execution order. */
    rules: string[];
    filesParsed: number | null;
    parseErrors: number | null;
  };
}

/** GET /api/scans/:id/stats */
export interface ScanStatsResponse {
  scanId: string;
  status: ScanStatus;
  /** Null while the scan is queued/running, or for a scan that predates statistics. */
  stats: ProjectStats | null;
  /** The failure reason of a failed scan. */
  error: string | null;
}
