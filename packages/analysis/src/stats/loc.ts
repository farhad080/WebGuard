import type { Language, LocCounts } from '@webguard/core';

/**
 * Line-based code/comment/blank split. A heuristic, like cloc's: a line is a comment when its
 * only content is a comment (or it lies inside a block comment); a line with code and a
 * trailing comment counts as code. Strings are not tokenized: a comment marker inside a string
 * on a code line is harmless (the line is still code), and a block comment only opens a
 * multi-line span when it starts a line. Template literals / heredocs whose lines start with a
 * comment marker are counted as comments. Good enough for an overview.
 */

interface CommentSyntax {
  line: string[];
  block: Array<[string, string]>;
}

const C_LIKE: CommentSyntax = { line: ['//'], block: [['/*', '*/']] };
const HASH: CommentSyntax = { line: ['#'], block: [] };
const MARKUP: CommentSyntax = { line: [], block: [['<!--', '-->']] };

const SYNTAX: Partial<Record<Language, CommentSyntax>> = {
  javascript: C_LIKE,
  typescript: C_LIKE,
  java: C_LIKE,
  go: C_LIKE,
  csharp: C_LIKE,
  css: { line: ['//'], block: [['/*', '*/']] },
  php: { line: ['//', '#'], block: [['/*', '*/']] },
  python: { line: ['#'], block: [] },
  ruby: { line: ['#'], block: [['=begin', '=end']] },
  shell: HASH,
  yaml: HASH,
  toml: HASH,
  dockerfile: HASH,
  terraform: { line: ['#', '//'], block: [['/*', '*/']] },
  sql: { line: ['--', '#'], block: [['/*', '*/']] },
  html: MARKUP,
  xml: MARKUP,
  markdown: MARKUP,
  vue: {
    line: ['//'],
    block: [
      ['<!--', '-->'],
      ['/*', '*/'],
    ],
  },
  svelte: {
    line: ['//'],
    block: [
      ['<!--', '-->'],
      ['/*', '*/'],
    ],
  },
  json: { line: [], block: [] },
};

export function emptyLoc(): LocCounts {
  return { code: 0, comment: 0, blank: 0, total: 0 };
}

export function addLoc(into: LocCounts, add: LocCounts): LocCounts {
  into.code += add.code;
  into.comment += add.comment;
  into.blank += add.blank;
  into.total += add.total;
  return into;
}

/** Number of lines (a trailing newline does not start another line). */
export function countLines(text: string): number {
  if (text === '') return 0;
  let n = 1;
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return text.endsWith('\n') ? n - 1 : n;
}

export function countLoc(text: string, language: Language): LocCounts {
  const syntax = SYNTAX[language] ?? { line: [], block: [] };
  const loc = emptyLoc();
  if (text === '') return loc;
  const lines = text.split(/\r?\n/);
  if (lines[lines.length - 1] === '') lines.pop();

  // The end marker of the block comment we are inside, if any.
  let inBlock: string | null = null;
  for (const raw of lines) {
    loc.total++;
    let line = raw.trim();
    if (line === '') {
      if (inBlock) loc.comment++;
      else loc.blank++;
      continue;
    }
    let hasCode = false;
    let hasComment = false;
    // Consume the line left to right: block-comment spans, a line comment, or code.
    while (line.length > 0) {
      if (inBlock) {
        hasComment = true;
        const end = line.indexOf(inBlock);
        if (end < 0) {
          line = '';
          break;
        }
        line = line.slice(end + inBlock.length).trim();
        inBlock = null;
        continue;
      }
      if (syntax.line.some((m) => line.startsWith(m))) {
        hasComment = true;
        break;
      }
      const opener = syntax.block.find(([open]) => line.startsWith(open));
      if (opener) {
        hasComment = true;
        inBlock = opener[1];
        line = line.slice(opener[0].length);
        continue;
      }
      // Code up to the next block-comment opener (which may start a multi-line comment).
      hasCode = true;
      let next = -1;
      let nextBlock: [string, string] | undefined;
      for (const b of syntax.block) {
        const i = line.indexOf(b[0]);
        if (i > 0 && (next < 0 || i < next)) {
          next = i;
          nextBlock = b;
        }
      }
      if (!nextBlock) break;
      // After code, only a comment that also closes on this line is taken as one: an unclosed
      // `/*` mid-line is far more often inside a string (globs: '**/*.js') than a real comment.
      const close = line.indexOf(nextBlock[1], next + nextBlock[0].length);
      if (close < 0) break;
      line = line.slice(close + nextBlock[1].length).trim();
    }
    if (hasCode) loc.code++;
    else if (hasComment) loc.comment++;
    else loc.blank++;
  }
  return loc;
}
