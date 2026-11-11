/** ISO-8601 timestamp string as serialized over the API. */
export type IsoDateString = string;

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Placeholder OWASP Top 10 (2021) categories; refined in a later step. */
export type OwaspCategory =
  | 'A01:2021-Broken Access Control'
  | 'A02:2021-Cryptographic Failures'
  | 'A03:2021-Injection'
  | 'A04:2021-Insecure Design'
  | 'A05:2021-Security Misconfiguration'
  | 'A06:2021-Vulnerable and Outdated Components'
  | 'A07:2021-Identification and Authentication Failures'
  | 'A08:2021-Software and Data Integrity Failures'
  | 'A09:2021-Security Logging and Monitoring Failures'
  | 'A10:2021-Server-Side Request Forgery';

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';

export type ArtifactKind = 'raw_zip' | 'extracted' | 'report';

export interface Project {
  id: string;
  userId: string;
  name: string;
  createdAt: IsoDateString;
}

/** Placeholder; the scan summary shape is defined once scanning exists. */
export type ScanSummary = Record<string, unknown>;

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
  createdAt: IsoDateString;
}

export interface Artifact {
  id: string;
  scanId: string;
  kind: ArtifactKind;
  storageKey: string;
  createdAt: IsoDateString;
}
