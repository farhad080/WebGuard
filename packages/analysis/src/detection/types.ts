import type {
  Finding,
  ManifestFile,
  OwaspCategory,
  ProjectProfile,
  SensitivePath,
  Severity,
  SourceFile,
} from '@webguard/core';
import type { ParsedFile } from '../ast/types.js';

/**
 * How a detector finds issues. The engine runs stages in exactly this order, so cheap,
 * broad passes run first and later stages (e.g. dataflow) can assume earlier ones ran.
 */
export const TECHNIQUE_STAGES = ['pattern', 'ast', 'dataflow', 'dependency', 'config'] as const;
export type Technique = (typeof TECHNIQUE_STAGES)[number];

/** Everything a detector may look at. Built once per scan and shared, read-only, by all detectors. */
export interface DetectionContext {
  readonly profile: ProjectProfile;
  /** Every file a parser adapter handled (check `ast`/`parseError`: some may have failed). */
  readonly files: readonly ParsedFile[];
  /** All profiled text files (code, config, markup), parsed or not. */
  readonly sourceFiles: readonly SourceFile[];
  readonly manifests: readonly ManifestFile[];
  /** Config / IaC / secrets / served paths found by the profiler. */
  readonly configPaths: readonly SensitivePath[];

  getParsedFile(path: string): ParsedFile | undefined;
  /**
   * Raw text of any extracted file (project-relative `/` path), or null if it doesn't exist,
   * is outside the project, or is larger than the read cap. Cached.
   */
  readText(path: string): string | null;
  /** Exact source lines `lineStart..lineEnd` (1-based, inclusive) of a file. */
  snippet(path: string, lineStart: number, lineEnd?: number): string;
}

/** What a detector reports. The engine validates it and fills in defaults from the detector. */
export interface RawFinding {
  detectorId: string;
  owaspCategory: OwaspCategory;
  severity: Severity;
  /** 0–1: how sure the detector is that this is a real issue (not a false positive). */
  confidence: number;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  /** Exact source of the flagged lines; use `ctx.snippet()`. Filled in by the engine if empty. */
  snippet: string;
  /** Short, specific reason, e.g. "req.body.name concatenated into db.query()". */
  evidence: string;
  /** Override the detector's default explanation / fix for this particular finding. */
  explanation?: string;
  fixSuggestion?: string;
}

export interface Detector {
  /** Stable, unique id, e.g. "A03-sql-injection". */
  id: string;
  title: string;
  owaspCategory: OwaspCategory;
  technique: Technique;
  /** Default explanation of the risk and default secure fix, used when a finding doesn't override. */
  explanation: string;
  fixSuggestion: string;
  run(ctx: DetectionContext): RawFinding[] | Promise<RawFinding[]>;
}

/** A RawFinding after engine validation: defaults applied, fields normalized. */
export type ValidatedFinding = RawFinding & { explanation: string; fixSuggestion: string };

/** Final, de-duplicated finding, ready to persist (the DB assigns id / scanId / createdAt). */
export type FindingDraft = Omit<Finding, 'id' | 'scanId' | 'createdAt'>;

export interface DetectorError {
  detectorId: string;
  stage: Technique;
  message: string;
}
