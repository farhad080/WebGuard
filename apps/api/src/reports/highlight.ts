/**
 * Tiny server-side syntax highlighter for report snippets. Snippets are untrusted code, so
 * every character is HTML-escaped; only our own <span class> wrappers are emitted.
 */

export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const KEYWORDS = new Set([
  'async', 'await', 'break', 'case', 'catch', 'class', 'const', 'continue', 'default', 'delete',
  'do', 'else', 'export', 'extends', 'false', 'finally', 'for', 'from', 'function', 'if',
  'import', 'in', 'instanceof', 'let', 'new', 'null', 'of', 'return', 'static', 'super',
  'switch', 'this', 'throw', 'true', 'try', 'typeof', 'undefined', 'var', 'void', 'while',
  'yield', 'interface', 'type', 'enum', 'public', 'private', 'protected', 'readonly',
  // python
  'def', 'elif', 'except', 'lambda', 'None', 'pass', 'raise', 'with', 'True', 'False', 'and',
  'or', 'not', 'is',
]); // prettier-ignore

const HASH_COMMENT_LANGUAGES = new Set(['python', 'yaml', 'shell', 'text', 'ruby']);

export function highlight(code: string, language: string): string {
  const hashComments = HASH_COMMENT_LANGUAGES.has(language);
  const token = new RegExp(
    [
      String.raw`(\/\/[^\n]*|\/\*[\s\S]*?\*\/${hashComments ? String.raw`|#[^\n]*` : ''})`, // 1 comment
      String.raw`('(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|` + '`(?:\\\\.|[^`\\\\])*`)', // 2 string
      String.raw`(\b\d+(?:\.\d+)?\b)`, // 3 number
      String.raw`([A-Za-z_$][\w$]*)`, // 4 word
    ].join('|'),
    'g',
  );
  let out = '';
  let last = 0;
  for (const m of code.matchAll(token)) {
    const index = m.index ?? 0;
    out += escapeHtml(code.slice(last, index));
    const [text, comment, string, number, word] = m;
    if (comment) out += `<span class="tc">${escapeHtml(comment)}</span>`;
    else if (string) out += `<span class="ts">${escapeHtml(string)}</span>`;
    else if (number) out += `<span class="tn">${escapeHtml(number)}</span>`;
    else if (word && KEYWORDS.has(word)) out += `<span class="tk">${escapeHtml(word)}</span>`;
    else out += escapeHtml(text);
    last = index + text.length;
  }
  return out + escapeHtml(code.slice(last));
}
