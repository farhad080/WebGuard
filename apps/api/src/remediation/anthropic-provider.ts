import Anthropic from '@anthropic-ai/sdk';
import type { RemediationLlmProvider } from '@webguard/analysis';

/**
 * Optional LLM assist for remediation: drafts a secure replacement for a flagged snippet.
 * Only constructed when REMEDIATION_LLM=true and an Anthropic API key is configured; the
 * deterministic templates never depend on it. Only the (already secret-redacted) flagged
 * snippet and the template's guidance are sent, never whole files.
 */
export class AnthropicRemediationProvider implements RemediationLlmProvider {
  readonly id = 'anthropic';
  private readonly client: Anthropic;

  constructor(
    apiKey: string,
    private readonly model = 'claude-opus-5-5',
  ) {
    this.client = new Anthropic({ apiKey, maxRetries: 1, timeout: 60_000 });
  }

  async draftSecureSnippet(input: {
    detectorId: string;
    title: string;
    language: string;
    before: string;
    why: string;
    steps: string[];
  }): Promise<string | undefined> {
    const response = await this.client.beta.messages.create({
      model: this.model,
      max_tokens: 16000,
      // Server-side fallback if the request is declined by a safety classifier.
      betas: ['server-side-fallback-2026-07-01'],
      fallbacks: 'default',
      // A short, mechanical rewrite: low effort is enough.
      output_config: { effort: 'low' },
      system:
        'You rewrite vulnerable code into a secure equivalent. Reply with only the rewritten ' +
        'code (no Markdown fences, no prose). Keep the original variable, function, and table ' +
        'names; change only what the fix requires. If a safe rewrite is impossible, reply with ' +
        'an empty message.',
      messages: [
        {
          role: 'user',
          content:
            `Vulnerability: ${input.title} (${input.detectorId})\n` +
            `Why it is vulnerable: ${input.why}\n` +
            `Fix steps:\n${input.steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}\n\n` +
            `Rewrite this ${input.language} code securely:\n${input.before}`,
        },
      ],
    });

    if (response.stop_reason === 'refusal' || response.stop_reason === 'max_tokens')
      return undefined;
    const text = response.content
      .map((block) => (block.type === 'text' ? block.text : ''))
      .join('')
      .trim();
    // Strip accidental Markdown fences.
    const unfenced = text.replace(/^```[\w-]*\n([\s\S]*?)\n```$/, '$1').trim();
    return unfenced || undefined;
  }
}
