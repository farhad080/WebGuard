/**
 * Worker-thread entry for one scan's analysis (see sandbox.ts). Runs with a V8 heap limit and
 * is terminated by the parent on timeout, so even a pathological input (e.g. catastrophic
 * regex backtracking, a parser blow-up) cannot hang or exhaust the worker process.
 *
 * The network guard is installed BEFORE any analysis module is loaded.
 */
import { parentPort, workerData } from 'node:worker_threads';
import type { AnalysisThreadInput, AnalysisThreadMessage } from './sandbox.js';

const input = workerData as AnalysisThreadInput;

async function main(): Promise<AnalysisThreadMessage> {
  const analyze = await import('./analyze.js');
  analyze.installNetworkGuard(analyze.allowedHosts(input.network, input.llm));
  try {
    const result = await analyze.analyzeProject(input.extractDir, {
      maxFileBytes: input.maxFileBytes,
      detectors: analyze.buildDetectorRegistry(input.network),
      remediation: await analyze.buildRemediation(input.llm),
      budget: {
        deadline: input.deadline,
        timeoutMs: input.timeoutMs,
        maxHeapBytes: input.maxHeapMb * 1024 * 1024 * 0.9,
      },
    });
    return { ok: true, result };
  } catch (err) {
    return {
      ok: false,
      limit: err instanceof analyze.ScanLimitError,
      message: err instanceof Error ? err.message : String(err),
      stack: err instanceof Error ? err.stack : undefined,
    };
  }
}

main().then(
  (message) => parentPort!.postMessage(message),
  (err: unknown) =>
    parentPort!.postMessage({
      ok: false,
      limit: false,
      message: err instanceof Error ? err.message : String(err),
    } satisfies AnalysisThreadMessage),
);
