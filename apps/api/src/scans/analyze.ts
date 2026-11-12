import {
  createDefaultDetectorRegistry,
  createDependencyDetector,
  createDetectionContext,
  dedupeFindings,
  DetectionEngine,
  DetectorRegistry,
  OsvAdvisorySource,
  parseSourceFiles,
  ProfilerService,
  RemediationService,
  SnapshotAdvisorySource,
  type EnrichedFinding,
  type ParsedFile,
} from '@webguard/analysis';
import type { DetectorErrorInfo, ParseErrorSample, ProjectProfile } from '@webguard/core';

/**
 * The analysis half of a scan: profile → parse → detect → de-dup → remediate, over an
 * already-extracted directory. It only READS the uploaded files (text + AST); nothing from
 * the upload is ever executed, required, or imported. Kept free of DB/queue imports so it can
 * run inside the isolated analysis thread (see sandbox.ts).
 */

/** A scan exceeded its time or memory budget. Its message is safe to show to the user. */
export class ScanLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScanLimitError';
  }
}

export interface AnalysisBudget {
  /** Epoch ms after which the analysis must stop. */
  deadline: number;
  /** Heap ceiling for the cooperative check (the thread also has a hard V8 limit). */
  maxHeapBytes?: number;
  /** Human-readable limits for error messages. */
  timeoutMs: number;
}

export function checkBudget(budget: AnalysisBudget | undefined): void {
  if (!budget) return;
  if (Date.now() > budget.deadline) {
    throw new ScanLimitError(
      `Scan exceeded the ${Math.round(budget.timeoutMs / 1000)} s time limit and was stopped`,
    );
  }
  if (budget.maxHeapBytes && process.memoryUsage().heapUsed > budget.maxHeapBytes) {
    throw new ScanLimitError(
      `Scan exceeded the ${Math.round(budget.maxHeapBytes / 1024 / 1024)} MB memory limit and was stopped`,
    );
  }
}

export interface NetworkSettings {
  /** Live OSV.dev lookups for dependencies (opt-in). */
  osv: boolean;
}

export interface LlmSettings {
  enabled: boolean;
  apiKey?: string;
  model?: string;
}

/** Built-in detectors; with OSV opted in, the dependency detector also queries OSV.dev. */
export function buildDetectorRegistry(network: NetworkSettings): DetectorRegistry {
  const registry = createDefaultDetectorRegistry();
  if (!network.osv) return registry;
  return new DetectorRegistry(
    registry.list().map((d) =>
      d.id === 'A11-vulnerable-deps'
        ? createDependencyDetector({
            sources: [
              new SnapshotAdvisorySource(),
              new OsvAdvisorySource({ allowNetwork: true, fetch: (u, i) => fetch(u, i) }),
            ],
          })
        : d,
    ),
  );
}

export async function buildRemediation(llm: LlmSettings): Promise<RemediationService> {
  if (!llm.enabled || !llm.apiKey) return new RemediationService({ llm: { enabled: false } });
  const { AnthropicRemediationProvider } = await import('../remediation/anthropic-provider.js');
  return new RemediationService({
    llm: { enabled: true, provider: new AnthropicRemediationProvider(llm.apiKey, llm.model) },
  });
}

/** Hosts the analysis may contact; everything else is refused (see installNetworkGuard). */
export function allowedHosts(network: NetworkSettings, llm: LlmSettings): string[] {
  const hosts: string[] = [];
  if (network.osv) hosts.push('api.osv.dev');
  if (llm.enabled) hosts.push('api.anthropic.com');
  return hosts;
}

/**
 * Defense in depth for the analysis thread: `fetch` only reaches the opted-in hosts. With
 * both features off (the default) the analysis cannot make any HTTP request through fetch.
 */
export function installNetworkGuard(hosts: readonly string[]): void {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (!hosts.includes(url.hostname)) {
      throw new Error(`Network access to ${url.hostname} is disabled for scans`);
    }
    return original(input, init);
  }) as typeof fetch;
}

export interface AnalysisOutput {
  profile: ProjectProfile;
  filesParsed: number;
  parseErrors: number;
  parseErrorSamples: ParseErrorSample[];
  detectors: string[];
  detectorErrors: DetectorErrorInfo[];
  findings: EnrichedFinding[];
}

export interface AnalyzeOptions {
  maxFileBytes: number;
  detectors: DetectorRegistry;
  remediation: RemediationService;
  budget?: AnalysisBudget;
}

const MAX_PARSE_ERROR_SAMPLES = 20;

export async function analyzeProject(
  extractDir: string,
  { maxFileBytes, detectors, remediation, budget }: AnalyzeOptions,
): Promise<AnalysisOutput> {
  // Analysis inputs: profile the project, then parse every supported source file.
  // A file that fails to parse is recorded and skipped; it never fails the scan.
  const profile = await new ProfilerService({ maxFileBytes }).profile(extractDir);
  checkBudget(budget);
  const files: ParsedFile[] = [];
  let parseErrors = 0;
  const parseErrorSamples: ParseErrorSample[] = [];
  for await (const file of parseSourceFiles(extractDir, profile)) {
    checkBudget(budget);
    files.push(file);
    if (file.parseError) {
      parseErrors++;
      if (parseErrorSamples.length < MAX_PARSE_ERROR_SAMPLES) {
        const { message, line, column } = file.parseError;
        parseErrorSamples.push({ path: file.path, message, line, column });
      }
    }
  }

  // Detection: every registered detector, stage by stage; then de-duplicate/correlate.
  // A failing detector is recorded in detectorErrors; it never fails the scan.
  const ctx = createDetectionContext({ rootDir: extractDir, profile, files });
  const engine = new DetectionEngine(detectors, { checkpoint: () => checkBudget(budget) });
  const detection = await engine.run(ctx);
  checkBudget(budget);

  // Remediation: why/impact, steps, a (contextualized) secure example and references.
  const findings = await remediation.enrichFindings(dedupeFindings(detection.findings), ctx);
  checkBudget(budget);

  return {
    profile,
    filesParsed: files.filter((f) => f.ast).length,
    parseErrors,
    parseErrorSamples,
    detectors: detection.executed,
    detectorErrors: detection.detectorErrors.map(({ detectorId, message }) => ({
      detectorId,
      message,
    })),
    findings,
  };
}
