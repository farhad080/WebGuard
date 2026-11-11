import { matchesName, walk } from './queries.js';
import type { AstNode, NodeTag } from './types.js';

/**
 * Lightweight, intra-procedural taint tracing.
 *
 * Given an expression (e.g. the SQL string passed to `db.query`), answers: can attacker-
 * controlled data reach it? It follows:
 *  - variables back to their assignments/declarations (including destructuring and
 *    `for...of`) in the enclosing function, then outward through enclosing scopes (closures);
 *  - string building: `+`, template literals, `?:`, `||` / `??`, string methods
 *    (`.substring()`, `.trim()`, `.replace(_, x)` ...), member reads on tainted objects;
 *  - unknown function calls conservatively (taint flows through, but is marked `throughCall`
 *    so detectors can lower confidence).
 *
 * Deliberately NOT handled (documented limitations): inter-procedural flow (calls into other
 * functions/files), aliasing through object mutation, array/collection element tracking, and
 * control-flow precision (all earlier assignments in scope are treated as reaching).
 */

export interface TaintOptions {
  /** Which nodes count as taint sources (default: tagged `source:http-input`). */
  isSource?: (node: AstNode) => boolean;
  /** Callee name patterns whose return value is safe (see `matchesName`). Added to defaults. */
  sanitizers?: readonly string[];
  /**
   * Treat scalar coercion as sanitizing: `String(x)`, `` `${x}` ``, `x + ''`, `x.toString()`.
   * Right for NoSQL operator injection (a string can't carry `{ $ne: ... }`), wrong for SQL.
   */
  coercionSanitizes?: boolean;
  /** Max assignment hops to follow (default 25). */
  maxHops?: number;
}

export interface TaintFlow {
  /** The source node that was reached (e.g. `req.body.email`). */
  source: AstNode;
  /** Variables traversed on the way, closest to the sink first, e.g. `['code', 'username']`. */
  via: string[];
  /** True when the flow passes through an unknown function call. */
  throughCall: boolean;
}

export interface TaintTrace {
  tainted: boolean;
  flows: TaintFlow[];
  /** At least one flow reaches a source without passing through an unknown call. */
  direct: boolean;
  /**
   * The value is not a compile-time constant: it depends on function parameters, imports or
   * globals, or call results. `false` means it's built only from literals/constants/enums.
   */
  dynamic: boolean;
}

/** Calls whose result can't carry an injection payload (numbers / booleans). */
const NUMERIC_SANITIZERS = [
  'Number',
  'parseInt',
  'parseFloat',
  'Boolean',
  'Number.parseInt',
  'Number.parseFloat',
  'Math.abs',
  'Math.floor',
  'Math.ceil',
  'Math.round',
  'Math.max',
  'Math.min',
  'isNaN',
  'Number.isInteger',
  'Array.isArray',
];

const SCALAR_COERCIONS = ['String', '*.toString', 'JSON.stringify'];

/** String methods whose result is derived from the receiver (and, for some, the arguments). */
const STRING_METHODS = new Set([
  'trim', 'trimStart', 'trimEnd', 'substring', 'substr', 'slice', 'toLowerCase', 'toUpperCase',
  'toLocaleLowerCase', 'toLocaleUpperCase', 'normalize', 'padStart', 'padEnd', 'repeat',
  'replace', 'replaceAll', 'concat', 'split', 'join', 'toString', 'valueOf', 'at', 'charAt',
]); // prettier-ignore
/** String methods whose *arguments* also flow into the result. */
const ARG_FLOW_METHODS = new Set(['replace', 'replaceAll', 'concat', 'padStart', 'padEnd', 'join']);

const TRANSPARENT_RAW = new Set([
  'TSAsExpression',
  'TSSatisfiesExpression',
  'TSNonNullExpression',
  'TSTypeAssertion',
  'ParenthesizedExpression',
  'AwaitExpression',
  'SpreadElement',
  'ExpressionStatement',
]);

const CONSTANT_GLOBALS = new Set(['undefined', 'NaN', 'Infinity']);
/** Values configured by the operator, not the attacker. */
const TRUSTED_ROOTS = /^(process\.env|Math|Number|JSON|Date|os|path)(\.|$)/;
/** Boolean/comparison operators produce booleans, never strings. */
const NON_PROPAGATING_BINARY = new Set([
  '==', '===', '!=', '!==', '<', '<=', '>', '>=', 'instanceof', 'in', '-', '*', '/', '%', '**',
  '|', '&', '^', '<<', '>>', '>>>',
]); // prettier-ignore

export const isHttpSource = (node: AstNode): boolean => node.tags.includes('source:http-input');

export function hasAnyTag(node: AstNode, tags: readonly NodeTag[]): boolean {
  return node.tags.some((t) => tags.includes(t));
}

// ---------------------------------------------------------------------------
// Scopes & definitions
// ---------------------------------------------------------------------------

function before(a: AstNode, b: AstNode): boolean {
  return (
    a.loc.startLine < b.loc.startLine ||
    (a.loc.startLine === b.loc.startLine && a.loc.startCol < b.loc.startCol)
  );
}

/** Enclosing functions, innermost first, then the Program. */
export function scopeChain(node: AstNode): AstNode[] {
  const scopes: AstNode[] = [];
  for (let p = node.parent; p; p = p.parent) {
    if (p.type === 'Function' || p.type === 'Program') scopes.push(p);
  }
  return scopes;
}

type RawPattern = { type: string; [k: string]: unknown } | null | undefined;

/** Identifier names bound by a (possibly destructuring) pattern, from the raw Babel node. */
function bindingNames(raw: RawPattern, out: string[] = []): string[] {
  if (!raw) return out;
  switch (raw.type) {
    case 'Identifier':
      out.push(raw.name as string);
      break;
    case 'ObjectPattern':
      for (const prop of raw.properties as RawPattern[]) {
        if (prop?.type === 'RestElement') bindingNames(prop.argument as RawPattern, out);
        else bindingNames(prop?.value as RawPattern, out);
      }
      break;
    case 'ArrayPattern':
      for (const el of raw.elements as RawPattern[]) bindingNames(el, out);
      break;
    case 'AssignmentPattern':
      bindingNames(raw.left as RawPattern, out);
      break;
    case 'RestElement':
      bindingNames(raw.argument as RawPattern, out);
      break;
    case 'VariableDeclaration':
      for (const d of raw.declarations as RawPattern[]) bindingNames(d?.id as RawPattern, out);
      break;
    case 'TSParameterProperty':
      bindingNames(raw.parameter as RawPattern, out);
      break;
  }
  return out;
}

export function parameterNames(fn: AstNode): string[] {
  const raw = fn.raw as { params?: RawPattern[] } | undefined;
  return (raw?.params ?? []).flatMap((p) => bindingNames(p));
}

interface Definition {
  /** The value expression that flows into the variable. */
  value: AstNode;
  /** The assignment/declaration node (for location). */
  at: AstNode;
}

const definitionCache = new WeakMap<AstNode, Map<string, Definition[]>>();

/** All assignments to `name` directly in `scope` (not inside nested functions). */
function definitionsIn(scope: AstNode, name: string): Definition[] {
  let byName = definitionCache.get(scope);
  if (!byName) {
    byName = new Map();
    definitionCache.set(scope, byName);
    const stack = [...scope.children];
    while (stack.length > 0) {
      const node = stack.pop()!;
      if (node.type === 'Function') continue; // nested scope
      if (node.type === 'Assignment' && node.left && node.right) {
        const names =
          node.left.type === 'Identifier'
            ? [node.left.name!]
            : bindingNames(node.left.raw as RawPattern);
        for (const n of names) push(byName, n, { value: node.right, at: node });
      } else if (node.rawType === 'ForOfStatement' || node.rawType === 'ForInStatement') {
        const [left, right] = node.children;
        if (left && right) {
          for (const n of bindingNames(left.raw as RawPattern)) {
            push(byName, n, { value: right, at: node });
          }
        }
      }
      for (const child of node.children) stack.push(child);
    }
  }
  return byName.get(name) ?? [];
}

function push(map: Map<string, Definition[]>, name: string, def: Definition): void {
  const list = map.get(name);
  if (list) list.push(def);
  else map.set(name, [def]);
}

export type Resolution =
  | { kind: 'definitions'; definitions: Definition[] }
  | { kind: 'parameter'; fn: AstNode }
  | { kind: 'unresolved' };

/**
 * Finds what an identifier refers to: assignments before this use in the innermost scope that
 * declares or assigns it, or a function parameter, or nothing (import / global).
 */
export function resolveIdentifier(identifier: AstNode): Resolution {
  const name = identifier.name;
  if (!name) return { kind: 'unresolved' };
  for (const scope of scopeChain(identifier)) {
    const defs = definitionsIn(scope, name).filter((d) => before(d.at, identifier));
    if (defs.length > 0) return { kind: 'definitions', definitions: defs };
    if (scope.type === 'Function' && parameterNames(scope).includes(name)) {
      return { kind: 'parameter', fn: scope };
    }
  }
  return { kind: 'unresolved' };
}

/** If `node` is a variable, the expressions assigned to it before this use; else `[node]`. */
export function resolveValues(node: AstNode): AstNode[] {
  if (node.type !== 'Identifier') return [node];
  const r = resolveIdentifier(node);
  return r.kind === 'definitions' ? r.definitions.map((d) => d.value) : [node];
}

/** `Status.ACTIVE`, `TABLE_NAME`, `Roles.Admin`: values that look like constants/enums. */
function looksConstant(node: AstNode): boolean {
  if (node.type === 'Identifier') {
    return /^[A-Z][A-Z0-9_]*$/.test(node.name ?? '') || CONSTANT_GLOBALS.has(node.name ?? '');
  }
  if (node.type === 'MemberAccess' && node.name) {
    const [root] = node.name.split('.');
    return (
      TRUSTED_ROOTS.test(node.name) ||
      (!!node.property && /^[A-Z][A-Z0-9_]*$/.test(node.property)) ||
      (!!root && /^[A-Z][A-Za-z0-9]*$/.test(root) && node.object?.type === 'Identifier')
    );
  }
  return false;
}

// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------

interface WorkItem {
  node: AstNode;
  via: string[];
  throughCall: boolean;
  hops: number;
}

export function traceTaint(expr: AstNode, options: TaintOptions = {}): TaintTrace {
  const isSource = options.isSource ?? isHttpSource;
  const sanitizers = [
    ...NUMERIC_SANITIZERS,
    ...(options.coercionSanitizes ? SCALAR_COERCIONS : []),
    ...(options.sanitizers ?? []),
  ];
  const maxHops = options.maxHops ?? 25;

  const flows: TaintFlow[] = [];
  let dynamic = false;
  const seen = new Set<AstNode>();
  const work: WorkItem[] = [{ node: expr, via: [], throughCall: false, hops: 0 }];

  while (work.length > 0) {
    const item = work.pop()!;
    const { node, via, throughCall, hops } = item;
    if (seen.has(node)) continue;
    seen.add(node);
    const next = (child: AstNode | undefined, extra: Partial<WorkItem> = {}) => {
      if (child) work.push({ node: child, via, throughCall, hops, ...extra });
    };

    // `.length` is a number even on tainted data (and `req.body.x.length` is itself tagged).
    if (node.type === 'MemberAccess' && node.property === 'length') continue;
    if (isSource(node)) {
      flows.push({ source: node, via, throughCall });
      continue;
    }
    if (TRANSPARENT_RAW.has(node.rawType)) {
      node.children.forEach((c) => next(c));
      continue;
    }

    switch (node.type) {
      case 'StringLiteral':
      case 'Literal':
        continue;

      case 'TemplateLiteral':
        if (options.coercionSanitizes) continue; // `${x}` is always a string
        for (const c of node.children) if (c.rawType !== 'TemplateElement') next(c);
        continue;

      case 'Binary': {
        const op = node.operator ?? '';
        if (NON_PROPAGATING_BINARY.has(op)) continue;
        if (
          options.coercionSanitizes &&
          op === '+' &&
          (node.left?.type === 'StringLiteral' || node.right?.type === 'StringLiteral')
        ) {
          continue; // x + '' is a string
        }
        next(node.left);
        next(node.right);
        continue;
      }

      case 'Identifier': {
        if (looksConstant(node)) continue;
        const resolution = resolveIdentifier(node);
        if (resolution.kind === 'definitions') {
          if (hops >= maxHops) {
            dynamic = true;
            continue;
          }
          for (const def of resolution.definitions) {
            next(def.value, { via: [...via, node.name!], hops: hops + 1 });
          }
        } else {
          dynamic = true; // parameter, import, or global: origin unknown in this file
        }
        continue;
      }

      case 'MemberAccess':
        if (looksConstant(node)) continue;
        if (node.property === 'length') continue; // a number
        next(node.object);
        continue;

      case 'Call': {
        if (sanitizers.some((p) => matchesName(node.name, p))) continue;
        dynamic = true;
        const callee = node.callee;
        const method = callee?.type === 'MemberAccess' ? callee.property : undefined;
        if (callee?.type === 'MemberAccess' && method && STRING_METHODS.has(method)) {
          if (options.coercionSanitizes && method === 'toString') continue;
          next(callee.object);
          if (ARG_FLOW_METHODS.has(method)) node.arguments?.forEach((a) => next(a));
        } else {
          // Unknown function: assume its result may carry its inputs, at lower confidence.
          if (callee?.type === 'MemberAccess') next(callee.object, { throughCall: true });
          node.arguments?.forEach((a) => next(a, { throughCall: true }));
        }
        continue;
      }

      case 'Object':
        for (const prop of node.children) {
          // Property: [key, value]; only values carry data.
          if (prop.type === 'Property') next(prop.children.at(-1));
          else next(prop);
        }
        continue;

      case 'Array':
        node.children.forEach((c) => next(c));
        continue;

      case 'Function':
        continue; // a function value isn't string data

      default:
        if (node.rawType === 'ConditionalExpression') {
          // test ? consequent : alternate — only the branches flow into the result
          next(node.children[1]);
          next(node.children[2]);
        } else if (node.rawType === 'UnaryExpression') {
          const op = (node.raw as { operator?: string }).operator;
          if (op !== 'typeof' && op !== '!' && op !== 'void' && op !== '-' && op !== '+') {
            node.children.forEach((c) => next(c));
          }
        } else if (node.rawType === 'SequenceExpression') {
          next(node.children.at(-1));
        } else if (node.rawType === 'ThisExpression') {
          dynamic = true;
        } else {
          dynamic = true;
          node.children.forEach((c) => next(c, { throughCall: true }));
        }
    }
  }

  return {
    tainted: flows.length > 0,
    flows,
    direct: flows.some((f) => !f.throughCall),
    dynamic: dynamic || flows.length > 0,
  };
}

/** The flattened parts of a `+` chain or template literal (or `[expr]` for anything else). */
export function stringParts(expr: AstNode): AstNode[] {
  const parts: AstNode[] = [];
  const stack = [expr];
  while (stack.length > 0) {
    const n = stack.pop()!;
    if (n.type === 'Binary' && n.operator === '+' && n.left && n.right) {
      stack.push(n.right, n.left);
    } else if (TRANSPARENT_RAW.has(n.rawType) && n.children[0]) {
      stack.push(n.children[0]);
    } else {
      parts.push(n);
    }
  }
  return parts;
}

/** Interpolated (non-literal) pieces of a string-building expression. */
export function interpolatedParts(expr: AstNode): AstNode[] {
  return stringParts(expr).flatMap((p) =>
    p.type === 'TemplateLiteral'
      ? p.children.filter((c) => c.rawType !== 'TemplateElement')
      : p.type === 'StringLiteral'
        ? []
        : [p],
  );
}

/** True for `a + b` chains and template literals with `${}`: strings built at runtime. */
export function isStringBuilding(expr: AstNode): boolean {
  return (
    interpolatedParts(expr).length > 0 &&
    (stringParts(expr).length > 1 || expr.type === 'TemplateLiteral')
  );
}

/** All nodes of an expression tree that are taint sources (for evidence). */
export function sourcesWithin(expr: AstNode, isSource = isHttpSource): AstNode[] {
  const out: AstNode[] = [];
  for (const n of walk(expr)) if (isSource(n)) out.push(n);
  return out;
}
