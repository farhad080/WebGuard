import { LineIndex } from '../ast/line-index.js';

export interface SnippetOptions {
  /** Extra lines of context before and after the range (default 0). */
  contextLines?: number;
  /** Hard caps so a huge range or minified line can't bloat a finding. */
  maxLines?: number;
  maxChars?: number;
}

export const MAX_SNIPPET_LINES = 20;
export const MAX_SNIPPET_CHARS = 2000;

/**
 * Returns the exact source text of lines `lineStart..lineEnd` (1-based, inclusive), joined
 * with `\n`. Out-of-range lines are clamped. Long output is truncated with a trailing `…`.
 */
export function getSnippet(
  source: string | LineIndex,
  lineStart: number,
  lineEnd: number = lineStart,
  options: SnippetOptions = {},
): string {
  const index = typeof source === 'string' ? new LineIndex(source) : source;
  const { contextLines = 0, maxLines = MAX_SNIPPET_LINES, maxChars = MAX_SNIPPET_CHARS } = options;

  const first = Math.max(1, Math.min(lineStart, lineEnd) - contextLines);
  const last = Math.min(index.lineCount, Math.max(lineStart, lineEnd) + contextLines);
  const lines: string[] = [];
  for (let line = first; line <= last && lines.length < maxLines; line++) {
    lines.push(index.lineText(line));
  }
  let text = lines.join('\n');
  const truncatedLines = last - first + 1 > maxLines;
  if (text.length > maxChars) text = `${text.slice(0, maxChars)}…`;
  else if (truncatedLines) text = `${text}\n…`;
  return text;
}
