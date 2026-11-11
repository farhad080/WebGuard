import type { AstNode, NodeTag, ParsedFile } from './types.js';

/** Accepts a parsed file, a node, or null (unparseable file → no results). */
export type QueryRoot = ParsedFile | AstNode | null | undefined;

function rootNode(root: QueryRoot): AstNode | null {
  if (!root) return null;
  return 'sourceText' in root ? root.ast : root;
}

/** Depth-first, pre-order traversal (iterative, so deep trees can't overflow the stack). */
export function* walk(root: QueryRoot): Generator<AstNode> {
  const start = rootNode(root);
  if (!start) return;
  const stack: AstNode[] = [start];
  while (stack.length > 0) {
    const node = stack.pop()!;
    yield node;
    for (let i = node.children.length - 1; i >= 0; i--) stack.push(node.children[i]!);
  }
}

export function findAll(root: QueryRoot, predicate: (node: AstNode) => boolean): AstNode[] {
  const out: AstNode[] = [];
  for (const node of walk(root)) if (predicate(node)) out.push(node);
  return out;
}

/**
 * Matches a dotted name against a pattern:
 *  - exact: `db.query` matches only `db.query`
 *  - any receiver: `*.query` matches `db.query`, `pool.query`, `this.db.query`, `?.query`
 *  - bare name: `eval` matches only `eval`
 */
export function matchesName(name: string | undefined, pattern: string): boolean {
  if (!name) return false;
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1); // ".query"
    return name.endsWith(suffix) && name.length > suffix.length;
  }
  return name === pattern;
}

/** Calls (incl. `new X()` and optional calls) whose callee matches any of the patterns. */
export function findCalls(root: QueryRoot, calleeNames: readonly string[]): AstNode[] {
  return findAll(root, (n) => n.type === 'Call' && calleeNames.some((p) => matchesName(n.name, p)));
}

export interface AssignmentQuery {
  /** Only assignments whose target name matches one of these patterns. */
  targets?: readonly string[];
  /** Include initialized declarations like `const x = 1` (default true). */
  includeDeclarations?: boolean;
}

/** `x = y`, `a.b += c`, and (by default) `const x = y`. */
export function findAssignments(root: QueryRoot, query: AssignmentQuery = {}): AstNode[] {
  const { targets, includeDeclarations = true } = query;
  return findAll(root, (n) => {
    if (n.type !== 'Assignment') return false;
    if (!includeDeclarations && n.rawType === 'VariableDeclarator') return false;
    return !targets || targets.some((p) => matchesName(n.left?.name, p));
  });
}

/** String literals and expression-free template literals. */
export function findStringLiterals(root: QueryRoot): AstNode[] {
  return findAll(
    root,
    (n) => n.type === 'StringLiteral' || (n.type === 'TemplateLiteral' && n.value !== undefined),
  );
}

/**
 * Assignments that write to a member, e.g. `el.innerHTML = x`.
 * A target is a property name (`innerHTML`) or a name pattern (`document.cookie`, `*.src`).
 */
export function findMemberWrites(root: QueryRoot, targets: readonly string[]): AstNode[] {
  return findAll(root, (n) => {
    if (n.type !== 'Assignment' || n.left?.type !== 'MemberAccess') return false;
    const left = n.left;
    return targets.some((t) => (t.includes('.') ? matchesName(left.name, t) : left.property === t));
  });
}

export function hasTag(node: AstNode, tag: NodeTag): boolean {
  return node.tags.includes(tag);
}

/** Nodes carrying a tag, or (with a trailing `*`) any tag with that prefix, e.g. `source:*`. */
export function findTagged(root: QueryRoot, tag: NodeTag): AstNode[] {
  const prefix = tag.endsWith('*') ? tag.slice(0, -1) : null;
  return findAll(root, (n) =>
    prefix ? n.tags.some((t) => t.startsWith(prefix)) : n.tags.includes(tag),
  );
}

/** True if the node or anything inside it is tagged as a taint source. */
export function containsSource(node: AstNode): boolean {
  for (const n of walk(node)) if (n.tags.some((t) => t.startsWith('source:'))) return true;
  return false;
}

/** Closest ancestor matching a predicate. */
export function findAncestor(
  node: AstNode,
  predicate: (node: AstNode) => boolean,
): AstNode | undefined {
  for (let p = node.parent; p; p = p.parent) if (predicate(p)) return p;
  return undefined;
}

/** Source text of a node. */
export function textOf(file: ParsedFile, node: AstNode): string {
  return file.lineIndex.slice(node.loc);
}
