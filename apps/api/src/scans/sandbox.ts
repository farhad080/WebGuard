import { Worker } from 'node:worker_threads';
import {
  ScanLimitError,
  type AnalysisOutput,
  type LlmSettings,
  type NetworkSettings,
} from './analyze.js';

export interface AnalysisThreadInput {
  extractDir: string;
  maxFileBytes: number;
  /** Default: the shared DEFAULT_IGNORED_DIRS. */
  ignoredDirs?: readonly string[];
  network: NetworkSettings;
  llm: LlmSettings;
  deadline: number;
  timeoutMs: number;
  maxHeapMb: number;
}

export type AnalysisThreadMessage =
  | { ok: true; result: AnalysisOutput }
  | { ok: false; limit: boolean; message: string; stack?: string };

export interface RunAnalysisThreadOptions {
  /** Hard heap cap for the thread (V8 old generation), in MB. */
  maxHeapMb: number;
  /** Wall-clock budget; the thread is terminated when it runs out. */
  timeoutMs: number;
  /** Override the thread entry (tests use hostile entries to prove the limits hold). */
  entry?: URL;
}

/** In development/tests this module runs from .ts (via tsx); in production from compiled .js. */
function defaultEntry(): URL {
  const fromSource = import.meta.url.endsWith('.ts');
  return new URL(fromSource ? './analysis-thread.ts' : './analysis-thread.js', import.meta.url);
}

/** A .ts entry is started through a bootstrap that registers tsx inside the thread. */
const TS_BOOTSTRAP = new URL('./ts-thread-bootstrap.mjs', import.meta.url);

/**
 * Runs a scan's analysis in a worker thread with a hard heap limit and a wall-clock timeout.
 * Exceeding either fails with a ScanLimitError (shown to the user as the scan's failure reason)
 * and the thread is torn down — the worker process itself is never at risk.
 */
export function runAnalysisInThread(
  input: Omit<AnalysisThreadInput, 'deadline' | 'timeoutMs' | 'maxHeapMb'>,
  options: RunAnalysisThreadOptions,
): Promise<AnalysisOutput> {
  const { timeoutMs, maxHeapMb } = options;
  const entry = options.entry ?? defaultEntry();
  const isTs = entry.pathname.endsWith('.ts');
  const workerData: AnalysisThreadInput = {
    ...input,
    deadline: Date.now() + timeoutMs,
    timeoutMs,
    maxHeapMb,
  };

  return new Promise<AnalysisOutput>((resolve, reject) => {
    const worker = new Worker(isTs ? TS_BOOTSTRAP : entry, {
      workerData: isTs ? { ...workerData, __tsEntry: entry.href } : workerData,
      resourceLimits: { maxOldGenerationSizeMb: maxHeapMb },
      stdout: false,
      stderr: false,
    });
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
      void worker.terminate();
    };
    const timer = setTimeout(
      () =>
        finish(() =>
          reject(
            new ScanLimitError(
              `Scan exceeded the ${Math.round(timeoutMs / 1000)} s time limit and was stopped`,
            ),
          ),
        ),
      timeoutMs,
    );

    worker.once('message', (msg: AnalysisThreadMessage) =>
      finish(() => {
        if (msg.ok) resolve(msg.result);
        else if (msg.limit) reject(new ScanLimitError(msg.message));
        else {
          const err = new Error(`Analysis failed: ${msg.message}`);
          if (msg.stack) err.stack = msg.stack;
          reject(err);
        }
      }),
    );
    worker.once('error', (err: Error & { code?: string }) =>
      finish(() =>
        reject(
          err.code === 'ERR_WORKER_OUT_OF_MEMORY'
            ? new ScanLimitError(`Scan exceeded the ${maxHeapMb} MB memory limit and was stopped`)
            : err,
        ),
      ),
    );
    worker.once('exit', (code) =>
      finish(() => reject(new Error(`Analysis thread exited unexpectedly (code ${code})`))),
    );
  });
}
