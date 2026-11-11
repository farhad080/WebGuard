import type { DetectorRegistry } from './registry.js';
import { clampConfidence, isSeverity } from './scoring.js';
import { MAX_SNIPPET_CHARS } from './snippet.js';
import {
  TECHNIQUE_STAGES,
  type DetectionContext,
  type Detector,
  type DetectorError,
  type RawFinding,
  type ValidatedFinding,
} from './types.js';

export interface EngineLogger {
  warn(message: string, ...details: unknown[]): void;
}

export interface EngineOptions {
  logger?: EngineLogger;
  /** A runaway detector can't flood the report (default 5,000 per detector). */
  maxFindingsPerDetector?: number;
}

export interface EngineResult {
  /** Validated raw findings, in stage order. Run `dedupeFindings()` to get the final list. */
  findings: ValidatedFinding[];
  detectorErrors: DetectorError[];
  /** Detector ids in the order they ran. */
  executed: string[];
  durationMs: number;
}

/**
 * Runs every registered detector, stage by stage (pattern → ast → dataflow → dependency →
 * config). Each detector is isolated: if it throws or returns garbage, that is recorded as a
 * non-fatal detector error and the remaining detectors still run.
 */
export class DetectionEngine {
  private readonly logger: EngineLogger;
  private readonly maxFindingsPerDetector: number;

  constructor(
    private readonly registry: DetectorRegistry,
    options: EngineOptions = {},
  ) {
    this.logger = options.logger ?? console;
    this.maxFindingsPerDetector = options.maxFindingsPerDetector ?? 5000;
  }

  async run(ctx: DetectionContext): Promise<EngineResult> {
    const started = Date.now();
    const findings: ValidatedFinding[] = [];
    const detectorErrors: DetectorError[] = [];
    const executed: string[] = [];

    for (const stage of TECHNIQUE_STAGES) {
      for (const detector of this.registry.byTechnique(stage)) {
        executed.push(detector.id);
        const fail = (message: string, err?: unknown) => {
          detectorErrors.push({ detectorId: detector.id, stage, message });
          this.logger.warn(
            `[detection] detector "${detector.id}" (${stage}): ${message}`,
            ...(err ? [err] : []),
          );
        };

        let output: unknown;
        try {
          output = await detector.run(ctx);
        } catch (err) {
          fail(`threw: ${err instanceof Error ? err.message : String(err)}`, err);
          continue;
        }
        if (!Array.isArray(output)) {
          fail('returned a non-array result');
          continue;
        }

        let accepted = 0;
        const rejections: string[] = [];
        for (const raw of output as unknown[]) {
          if (accepted >= this.maxFindingsPerDetector) {
            fail(`exceeded ${this.maxFindingsPerDetector} findings; the rest were dropped`);
            break;
          }
          const result = validateFinding(detector, raw, ctx);
          if (typeof result === 'string') rejections.push(result);
          else {
            findings.push(result);
            accepted++;
          }
        }
        if (rejections.length > 0) {
          fail(`${rejections.length} invalid finding(s) dropped; first: ${rejections[0]}`);
        }
      }
    }

    return { findings, detectorErrors, executed, durationMs: Date.now() - started };
  }
}

/** Returns a normalized finding, or a string describing why it was rejected. */
function validateFinding(
  detector: Detector,
  value: unknown,
  ctx: DetectionContext,
): ValidatedFinding | string {
  if (!value || typeof value !== 'object') return 'finding is not an object';
  const f = value as Partial<RawFinding>;

  if (typeof f.filePath !== 'string' || ctx.readText(f.filePath) === null) {
    return `unknown file ${JSON.stringify(f.filePath)}`;
  }
  const lineStart = f.lineStart;
  const lineEnd = f.lineEnd ?? lineStart;
  if (
    !Number.isInteger(lineStart) ||
    !Number.isInteger(lineEnd) ||
    lineStart! < 1 ||
    lineEnd! < lineStart!
  ) {
    return `invalid line range ${lineStart}-${lineEnd} in ${f.filePath}`;
  }
  const severity = f.severity;
  if (!isSeverity(severity)) return `invalid severity ${JSON.stringify(severity)}`;
  if (typeof f.confidence !== 'number' || !Number.isFinite(f.confidence)) {
    return `invalid confidence ${JSON.stringify(f.confidence)}`;
  }

  const snippet =
    typeof f.snippet === 'string' && f.snippet.length > 0
      ? f.snippet
      : ctx.snippet(f.filePath, lineStart!, lineEnd!);

  return {
    // A detector can only report under its own id.
    detectorId: detector.id,
    owaspCategory: f.owaspCategory ?? detector.owaspCategory,
    cwe: f.cwe ?? detector.cwe,
    severity,
    confidence: clampConfidence(f.confidence),
    filePath: f.filePath,
    lineStart: lineStart!,
    lineEnd: lineEnd!,
    snippet:
      snippet.length > MAX_SNIPPET_CHARS ? `${snippet.slice(0, MAX_SNIPPET_CHARS)}…` : snippet,
    evidence: typeof f.evidence === 'string' ? f.evidence : '',
    explanation: f.explanation || detector.explanation,
    fixSuggestion: f.fixSuggestion || detector.fixSuggestion,
  };
}
