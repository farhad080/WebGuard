import type { RemediationReference } from '@webguard/core';
import type { ParsedFile } from '../ast/types.js';
import type { FindingDraft } from '../detection/types.js';

/** A fix template: deterministic, offline, reviewed content for one vulnerability class. */
export interface FixTemplate {
  /** Stable id, e.g. "A1-sql-injection" or "A6-weak-crypto/password". */
  id: string;
  title: string;
  why: string;
  impact: string;
  steps: string[];
  example: { language: string; before: string; after: string };
  references: RemediationReference[];
}

export interface ContextualExample {
  before: string;
  after: string;
  note?: string;
}

export interface ContextInput {
  finding: FindingDraft;
  /** The parsed file the finding points at, when available. */
  file?: ParsedFile;
}

/** All fix content for one detector, with optional variants (e.g. by CWE or finding kind). */
export interface TemplateSet {
  detectorId: string;
  default: FixTemplate;
  variants?: Record<string, FixTemplate>;
  /** Picks a variant key for a finding (default: the finding's CWE). */
  select?: (finding: FindingDraft) => string | undefined;
  /**
   * Rewrites the finding's own code into the secure form. Returns undefined when a safe,
   * faithful rewrite isn't possible (the generic template example is used instead).
   */
  contextualize?: (input: ContextInput) => ContextualExample | undefined;
}

/** Optional LLM that drafts a contextual `after` snippet when no deterministic rewrite exists. */
export interface RemediationLlmProvider {
  readonly id: string;
  draftSecureSnippet(input: {
    detectorId: string;
    title: string;
    language: string;
    /** The flagged code (already redacted for secrets). */
    before: string;
    why: string;
    steps: string[];
  }): Promise<string | undefined>;
}
