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

/**
 * Name of the function containing `node`: a declaration name, or the variable / property /
 * method it is assigned to (`export const hash = (data) => …` → `hash`).
 */
export function enclosingFunction(node: AstNode): { fn: AstNode; name?: string } | undefined {
  for (let p = node.parent; p; p = p.parent) {
    if (p.type !== 'Function') continue;
    if (p.name) return { fn: p, name: p.name };
    const parent = p.parent;
    if (parent?.type === 'Assignment' && parent.right === p) {
      return { fn: p, name: parent.name?.split('.').at(-1) };
    }
    if (parent?.type === 'Property') {
      const key = (parent.raw as { key?: { name?: string; value?: string } }).key;
      return { fn: p, name: key?.name ?? key?.value };
    }
    return { fn: p };
  }
  return undefined;
}

/** Test code, fixtures, mocks and e2e specs: secrets there are expected and not shipped. */
export function isTestPath(path: string): boolean {
  return (
    /(^|\/)(tests?|__tests__|specs?|fixtures?|__fixtures__|mocks?|__mocks__|e2e|cypress)\//i.test(
      path,
    ) || /\.(test|spec|e2e)\.[cm]?[jt]sx?$/i.test(path)
  );
}

const CLIENT_DIR =
  /(^|\/)(frontend|front-end|client|public|static|www|wwwroot|htdocs|public_html|browser|webapp)\//i;
const CLIENT_EXT = /\.(jsx|tsx|vue|svelte|html?)$/i;
const CLIENT_IMPORT =
  /from\s+['"](@angular\/|react(-dom)?['"/]|vue['"]|svelte)|require\(['"]react['"]\)/;

/**
 * Whether a file ends up in the browser: under a served/static dir (profiler), in a
 * front-end directory, a component file, or code importing Angular/React/Vue/Svelte.
 */
export function isClientSide(ctx: DetectionContext, path: string): boolean {
  if (ctx.configPaths.some((p) => p.path === path && p.category === 'static-served')) return true;
  if (CLIENT_DIR.test(path) || CLIENT_EXT.test(path)) return true;
  const text = ctx.readText(path);
  return text !== null && CLIENT_IMPORT.test(text);
}

/** `AKIA2E0A…[redacted, 20 chars]`: enough to recognise, useless to an attacker. */
export function redact(value: string, keep = 4): string {
  const shown =
    value.length > 12 ? value.slice(0, keep) : value.slice(0, Math.min(2, value.length));
  return `${shown}…[redacted, ${value.length} chars]`;
}
