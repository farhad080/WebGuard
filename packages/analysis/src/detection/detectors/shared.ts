import { textOf } from '../../ast/queries.js';
import type { TaintFlow, TaintTrace } from '../../ast/taint.js';
import type { AstNode, ParsedFile } from '../../ast/types.js';
import type { DetectionContext, RawFinding } from '../types.js';

/** Parsed files that produced an AST. */
export function parsedFiles(ctx: DetectionContext): ParsedFile[] {
  return ctx.files.filter((f): f is ParsedFile & { ast: AstNode } => f.ast !== null);
}

export function shorten(text: string, max = 120): string {
  const oneLine = text.replace(/\s+/g, ' ').trim();
  return oneLine.length > max ? `${oneLine.slice(0, max - 1)}…` : oneLine;
}

/** "`criteria` ← criteria ← req.query.q", for evidence. */
export function describeFlow(file: ParsedFile, part: AstNode, flow: TaintFlow): string {
  const partText = shorten(textOf(file, part), 80);
  const sourceText = shorten(textOf(file, flow.source), 60);
  const chain = [...flow.via, sourceText].filter((v, i, a) => a.indexOf(v) === i);
  const through = flow.throughCall ? ' (through a function call)' : '';
  return partText === sourceText
    ? `\`${partText}\`${through}`
    : `\`${partText}\` ← ${chain.join(' ← ')}${through}`;
}

/** The most convincing flow: direct before through-call, then shortest. */
export function bestFlow(trace: TaintTrace): TaintFlow | undefined {
  return [...trace.flows].sort(
    (a, b) => Number(a.throughCall) - Number(b.throughCall) || a.via.length - b.via.length,
  )[0];
}

export function findingAt(
  ctx: DetectionContext,
  file: ParsedFile,
  node: AstNode,
  fields: Omit<RawFinding, 'filePath' | 'lineStart' | 'lineEnd' | 'snippet'>,
): RawFinding {
  return {
    ...fields,
    filePath: file.path,
    lineStart: node.loc.startLine,
    lineEnd: node.loc.endLine,
    snippet: ctx.snippet(file.path, node.loc.startLine, node.loc.endLine),
  };
}
