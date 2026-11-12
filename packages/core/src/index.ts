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
