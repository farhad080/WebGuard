import type { Remediation } from '@webguard/core';
import type { DetectionContext, EnrichedFinding, FindingDraft } from '../detection/types.js';
import { REFS } from './references.js';
import { TEMPLATE_SETS } from './templates.js';
import type { FixTemplate, RemediationLlmProvider, TemplateSet } from './types.js';

export interface RemediationOptions {
  /** Extra / overriding template sets (keyed by detectorId). */
  templates?: readonly TemplateSet[];
  /**
   * Optional LLM assist. Used only when `enabled` is true AND a provider is given; otherwise
   * nothing leaves the process. Drafts an `after` snippet only for findings the deterministic
   * contextualizers could not rewrite.
   */
  llm?: { enabled: boolean; provider?: RemediationLlmProvider; maxCalls?: number };
  logger?: { warn(message: string, ...details: unknown[]): void };
}

const LANGUAGE_BY_EXT: Record<string, string> = {
  ts: 'typescript', tsx: 'typescript', js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
  json: 'json', py: 'python', php: 'php', html: 'html', yml: 'yaml', yaml: 'yaml',
}; // prettier-ignore

function languageOf(path: string, fallback: string): string {
  return LANGUAGE_BY_EXT[path.split('.').at(-1)?.toLowerCase() ?? ''] ?? fallback;
}

/** For findings from detectors without a template (custom/third-party detectors). */
function genericTemplate(finding: FindingDraft): FixTemplate {
  return {
    id: `${finding.detectorId}/generic`,
    title: 'Fix the reported issue',
    why: finding.explanation,
    impact: 'See the explanation: impact depends on the vulnerability class.',
    steps: [
      'Review the flagged code and the evidence.',
      finding.fixSuggestion,
      'Add a regression test and re-run the scan.',
    ],
    example: { language: 'text', before: finding.snippet, after: finding.fixSuggestion },
    references: [REFS.nodejs],
  };
}

/**
 * Turns findings into developer-ready fixes: why/impact, a numbered remediation algorithm, a
 * secure before/after example (rewritten from the finding's own code where possible), and
 * OWASP references. Fully deterministic and offline unless the LLM assist is explicitly on.
 */
export class RemediationService {
  private readonly sets = new Map<string, TemplateSet>();
  private readonly llm: RemediationOptions['llm'];
  private readonly logger: NonNullable<RemediationOptions['logger']>;

  constructor(options: RemediationOptions = {}) {
    for (const set of [...TEMPLATE_SETS, ...(options.templates ?? [])])
      this.sets.set(set.detectorId, set);
    this.llm = options.llm;
    this.logger = options.logger ?? console;
  }

  hasTemplate(detectorId: string): boolean {
    return this.sets.has(detectorId);
  }

  /** Template only (no contextualization / LLM). */
  resolveTemplate(finding: FindingDraft): FixTemplate {
    const set = this.sets.get(finding.detectorId);
    if (!set) return genericTemplate(finding);
    const key = set.select ? set.select(finding) : (finding.cwe ?? undefined);
    return (key && set.variants?.[key]) || set.default;
  }

  /** Deterministic remediation for one finding. */
  remediate(finding: FindingDraft, ctx?: DetectionContext): Remediation {
    const template = this.resolveTemplate(finding);
    const set = this.sets.get(finding.detectorId);
    let contextual;
    try {
      contextual = set?.contextualize?.({ finding, file: ctx?.getParsedFile(finding.filePath) });
    } catch (err) {
      // A rewrite must never break the scan: fall back to the generic example.
      this.logger.warn(`[remediation] contextualize failed for ${finding.detectorId}`, err);
    }
    const steps = [...template.steps];
    return {
      templateId: template.id,
      title: template.title,
      why: template.why,
      impact: template.impact,
      steps,
      secureExample: contextual
        ? {
            language: languageOf(finding.filePath, template.example.language),
            before: contextual.before,
            after: contextual.after,
            contextualized: true,
            ...(contextual.note ? { note: contextual.note } : {}),
          }
        : { ...template.example, contextualized: false },
      references: template.references,
      generatedBy: contextual ? 'template+context' : 'template',
    };
  }

  /**
   * Attaches remediation to every finding (before persistence). The optional LLM drafts an
   * `after` snippet only for findings without a deterministic rewrite, and only when enabled.
   */
  async enrichFindings(
    findings: readonly FindingDraft[],
    ctx?: DetectionContext,
  ): Promise<EnrichedFinding[]> {
    const enriched = findings.map((f) => ({ ...f, remediation: this.remediate(f, ctx) }));
    const { enabled, provider, maxCalls = 20 } = this.llm ?? { enabled: false };
    if (!enabled || !provider) return enriched;

    let calls = 0;
    for (const f of enriched) {
      if (f.remediation.secureExample.contextualized || calls >= maxCalls) continue;
      calls++;
      try {
        const after = await provider.draftSecureSnippet({
          detectorId: f.detectorId,
          title: f.remediation.title,
          language: languageOf(f.filePath, f.remediation.secureExample.language),
          before: f.snippet, // already redacted for secrets by the detectors
          why: f.remediation.why,
          steps: f.remediation.steps,
        });
        if (after && after.trim()) {
          f.remediation = {
            ...f.remediation,
            secureExample: {
              language: languageOf(f.filePath, f.remediation.secureExample.language),
              before: f.snippet.trim(),
              after: after.trim(),
              contextualized: true,
              note: `Drafted by ${provider.id}; review before applying.`,
            },
            generatedBy: 'llm',
          };
        }
      } catch (err) {
        // The deterministic template stays in place.
        this.logger.warn(`[remediation] LLM draft failed for ${f.detectorId}`, err);
      }
    }
    return enriched;
  }
}

/** Every detector id that has a dedicated template set. */
export const TEMPLATE_DETECTOR_IDS: readonly string[] = TEMPLATE_SETS.map((s) => s.detectorId);
