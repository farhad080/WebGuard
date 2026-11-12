import path from 'node:path';

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function positiveNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`Environment variable ${name} must be a positive number`);
  }
  return value;
}

const MiB = 1024 * 1024;

// Getters read the environment lazily so tests and entrypoints can set it first.
export const config = {
  get port(): number {
    return Number(process.env.PORT ?? 3000);
  },
  get jwtSecret(): string {
    return required('JWT_SECRET');
  },
  jwtExpiresIn: '1h' as const,
  /** Public URL of the web app (used in password-reset links). */
  get appBaseUrl(): string {
    return (process.env.APP_BASE_URL ?? 'http://localhost:5173').replace(/\/+$/, '');
  },

  get redisUrl(): string {
    return process.env.REDIS_URL ?? 'redis://localhost:6379';
  },
  get scanQueueName(): string {
    return process.env.SCAN_QUEUE_NAME ?? 'scans';
  },

  /** Root directory for the local-filesystem StorageService (relative paths resolve from cwd). */
  get storageDir(): string {
    return path.resolve(process.env.STORAGE_DIR ?? 'storage');
  },
  get maxUploadBytes(): number {
    return positiveNumber('MAX_UPLOAD_BYTES', 50 * MiB);
  },

  /**
   * Optional LLM assist for remediation snippets. Off unless REMEDIATION_LLM=true AND an
   * Anthropic API key is set; no code leaves the server otherwise.
   */
  get remediationLlm(): { enabled: boolean; apiKey?: string; model?: string } {
    const apiKey = process.env.ANTHROPIC_API_KEY || undefined;
    return {
      enabled: process.env.REMEDIATION_LLM === 'true' && apiKey !== undefined,
      apiKey,
      model: process.env.REMEDIATION_LLM_MODEL || undefined,
    };
  },

  /** Preinstalled Chromium for PDF reports (auto-detected when unset; never downloaded). */
  get chromiumPath(): string | undefined {
    return process.env.CHROMIUM_PATH || undefined;
  },
  /** How long GET report.pdf waits for the worker before answering 202 (default 60 s). */
  get reportPdfWaitMs(): number {
    return positiveNumber('REPORT_PDF_WAIT_MS', 60_000);
  },
  /** Pre-render the PDF report when a scan completes (default on). */
  get reportPdfOnComplete(): boolean {
    return process.env.REPORT_PDF_ON_COMPLETE !== 'false';
  },

  /** Source files larger than this are profiled but not parsed (minified/generated code). */
  get analysisMaxFileBytes(): number {
    return positiveNumber('ANALYSIS_MAX_FILE_BYTES', 1 * MiB);
  },

  get extraction() {
    return {
      maxTotalBytes: positiveNumber('EXTRACT_MAX_TOTAL_BYTES', 500 * MiB),
      maxFiles: positiveNumber('EXTRACT_MAX_FILES', 20_000),
      maxCompressionRatio: positiveNumber('EXTRACT_MAX_COMPRESSION_RATIO', 100),
      ratioCheckMinBytes: positiveNumber('EXTRACT_RATIO_CHECK_MIN_BYTES', 1 * MiB),
    };
  },
};
