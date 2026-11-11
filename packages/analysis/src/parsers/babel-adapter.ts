import babelParser, { type ParserPlugin } from '@babel/parser';
import babelTypes, { type Node as BabelNode } from '@babel/types';
import type { AstNode, NodeType } from '../ast/types.js';
import type { AdapterResult, ParseInput, ParserAdapter } from './registry.js';

/**
 * JavaScript/TypeScript adapter built on @babel/parser.
 *
 * Why Babel (vs. ts-morph or tree-sitter):
 *  - One parser for JS, JSX, TS, and TSX, including decorators (Angular/Nest) and the latest
 *    syntax, with exact line/column locations.
 *  - `errorRecovery` keeps producing an AST for files with some syntax errors, so a single bad
 *    file degrades gracefully instead of hiding the whole file.
 *  - Pure JS and fast: no native bindings or WASM (unlike tree-sitter), and no TypeScript
 *    program/type-checker to build (unlike ts-morph). Detectors here are syntactic plus
 *    taint tags, so full type information isn't needed.
 */
export class BabelJsTsAdapter implements ParserAdapter {
  readonly id = 'babel-js-ts';
  readonly languages = ['javascript', 'typescript'] as const;

  parse(input: ParseInput): AdapterResult {
    let file: ReturnType<typeof babelParser.parse>;
    try {
      file = babelParser.parse(input.sourceText, {
        sourceType: 'unambiguous',
        plugins: pluginsFor(input),
        errorRecovery: true,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
        allowImportExportEverywhere: true,
        allowSuperOutsideMethod: true,
        allowUndeclaredExports: true,
        attachComment: false,
      });
    } catch (err) {
      // Unrecoverable syntax error: no AST, but keep Babel's position for the report.
      const e = err as BabelError;
      return { ast: null, parseError: { ...errorPosition(e), recovered: false } };
    }

    const ast = convert(file.program);
    const firstError = file.errors?.[0] as BabelError | undefined;
    return {
      ast,
      parseError: firstError ? { ...errorPosition(firstError), recovered: true } : undefined,
    };
  }
}

type BabelError = Error & { loc?: { line: number; column: number } };

function errorPosition(err: BabelError): { message: string; line?: number; column?: number } {
  return {
    message: err instanceof Error ? err.message : String(err),
    line: err.loc?.line,
    column: err.loc?.column,
  };
}

function pluginsFor({ path, language }: ParseInput): ParserPlugin[] {
  const lower = path.toLowerCase();
  if (language === 'typescript') {
    // JSX only for .tsx: in .ts files `<T>value` is a type assertion, not JSX.
    return lower.endsWith('.tsx')
      ? ['typescript', 'jsx', 'decorators-legacy']
      : ['typescript', 'decorators-legacy'];
  }
  return ['jsx', 'decorators-legacy'];
}

const TYPE_MAP: Record<string, NodeType> = {
  Program: 'Program',
  FunctionDeclaration: 'Function',
  FunctionExpression: 'Function',
  ArrowFunctionExpression: 'Function',
  ObjectMethod: 'Function',
  ClassMethod: 'Function',
  ClassPrivateMethod: 'Function',
  CallExpression: 'Call',
  OptionalCallExpression: 'Call',
  NewExpression: 'Call',
  MemberExpression: 'MemberAccess',
  OptionalMemberExpression: 'MemberAccess',
  AssignmentExpression: 'Assignment',
  Identifier: 'Identifier',
  StringLiteral: 'StringLiteral',
  DirectiveLiteral: 'StringLiteral',
  TemplateLiteral: 'TemplateLiteral',
  NumericLiteral: 'Literal',
  BooleanLiteral: 'Literal',
  NullLiteral: 'Literal',
  RegExpLiteral: 'Literal',
  BigIntLiteral: 'Literal',
  BinaryExpression: 'Binary',
  LogicalExpression: 'Binary',
  ObjectExpression: 'Object',
  ArrayExpression: 'Array',
  ObjectProperty: 'Property',
  ImportDeclaration: 'Import',
  ReturnStatement: 'Return',
  BlockStatement: 'Block',
};

/** TS/paren wrappers that don't change which value an expression refers to. */
const TRANSPARENT = new Set([
  'TSAsExpression',
  'TSSatisfiesExpression',
  'TSNonNullExpression',
  'TSTypeAssertion',
  'ParenthesizedExpression',
]);

type AnyNode = BabelNode & Record<string, unknown>;

function unwrap(node: AnyNode): AnyNode {
  let n = node;
  while (TRANSPARENT.has(n.type)) n = n.expression as AnyNode;
  return n;
}

function staticKey(node: AnyNode): string | undefined {
  if (node.type === 'StringLiteral') return node.value as string;
  if (node.type === 'NumericLiteral') return String(node.value);
  if (node.type === 'TemplateLiteral' && (node.expressions as unknown[]).length === 0) {
    return ((node.quasis as AnyNode[])[0]?.value as { cooked?: string }).cooked ?? undefined;
  }
  return undefined;
}

function propertyName(member: AnyNode): string | undefined {
  const prop = member.property as AnyNode;
  if (!member.computed) {
    if (prop.type === 'Identifier') return prop.name as string;
    if (prop.type === 'PrivateName') return `#${(prop.id as AnyNode).name as string}`;
    return undefined;
  }
  return staticKey(prop);
}

/**
 * Dotted path of an expression: `req.body.name`, `this.db.query`, `?.query` for dynamic parts.
 * Iterative, so very long member chains can't overflow the stack.
 */
function pathOf(input: AnyNode): string {
  const parts: string[] = [];
  let node = unwrap(input);
  while (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    parts.push(propertyName(node) ?? '?');
    node = unwrap(node.object as AnyNode);
  }
  let head: string;
  if (node.type === 'Identifier') head = node.name as string;
  else if (node.type === 'ThisExpression') head = 'this';
  else if (node.type === 'Super') head = 'super';
  else head = '?';
  return [head, ...parts.reverse()].join('.');
}

function hide(node: AstNode, key: 'parent' | 'raw', value: unknown): void {
  Object.defineProperty(node, key, { value, enumerable: false, writable: false });
}

function isBabelNode(value: unknown): value is BabelNode {
  return !!value && typeof value === 'object' && 'type' in value;
}

interface Pending {
  b: BabelNode;
  parent?: AstNode;
  /** Where to record the child on the parent: a single slot or an array slot. */
  slot?: { byKey: Record<string, AstNode | AstNode[]>; key: string; isArray: boolean };
}

/**
 * Converts a Babel tree into the common AST with an explicit stack (no recursion), so deeply
 * nested code such as minified bundles or long `a + b + c ...` chains can't overflow.
 */
function convert(rootBabel: BabelNode): AstNode {
  const created: Array<{ node: AstNode; b: AnyNode; byKey: Record<string, AstNode | AstNode[]> }> =
    [];
  const stack: Pending[] = [{ b: rootBabel }];
  let root: AstNode | undefined;

  while (stack.length > 0) {
    const { b: input, parent, slot } = stack.pop()!;
    const b = input as AnyNode;
    const loc = b.loc;
    const node: AstNode = {
      type: TYPE_MAP[b.type] ?? 'Other',
      rawType: b.type,
      loc: {
        startLine: loc?.start.line ?? 1,
        startCol: loc?.start.column ?? 0,
        endLine: loc?.end.line ?? 1,
        endCol: loc?.end.column ?? 0,
      },
      children: [],
      tags: [],
    };
    hide(node, 'parent', parent);
    hide(node, 'raw', input);

    if (parent && slot) {
      // Children are popped in source order (pushed in reverse below), so appending keeps order.
      parent.children.push(node);
      if (slot.isArray) (slot.byKey[slot.key] as AstNode[]).push(node);
      else slot.byKey[slot.key] = node;
    } else {
      root = node;
    }

    const byKey: Record<string, AstNode | AstNode[]> = {};
    created.push({ node, b, byKey });

    const toPush: Pending[] = [];
    for (const key of babelTypes.VISITOR_KEYS[b.type] ?? []) {
      const value = b[key];
      if (Array.isArray(value)) {
        byKey[key] = [];
        for (const item of value) {
          if (isBabelNode(item))
            toPush.push({ b: item, parent: node, slot: { byKey, key, isArray: true } });
        }
      } else if (isBabelNode(value)) {
        toPush.push({ b: value, parent: node, slot: { byKey, key, isArray: false } });
      }
    }
    for (let i = toPush.length - 1; i >= 0; i--) stack.push(toPush[i]!);
  }

  for (const { node, b, byKey } of created) fillSemantics(node, b, byKey);
  return root!;
}

/** Populates the normalized fields (callee, name, left/right, ...) once children exist. */
function fillSemantics(
  node: AstNode,
  b: AnyNode,
  byKey: Record<string, AstNode | AstNode[]>,
): void {
  const one = (key: string) => (Array.isArray(byKey[key]) ? undefined : byKey[key]);
  switch (node.type) {
    case 'Call':
      node.callee = one('callee');
      node.arguments = (byKey.arguments as AstNode[] | undefined) ?? [];
      node.name = pathOf(b.callee as AnyNode);
      break;
    case 'MemberAccess':
      node.object = one('object');
      node.computed = Boolean(b.computed);
      node.property = propertyName(b);
      node.name = pathOf(b);
      break;
    case 'Assignment':
      node.left = one('left');
      node.right = one('right');
      node.operator = b.operator as string;
      node.name = node.left ? pathOf(b.left as AnyNode) : undefined;
      break;
    case 'Binary':
      node.left = one('left');
      node.right = one('right');
      node.operator = b.operator as string;
      break;
    case 'Identifier':
      node.name = b.name as string;
      break;
    case 'StringLiteral':
      node.value = b.value as string;
      break;
    case 'TemplateLiteral':
      node.value = staticKey(b);
      break;
    case 'Function': {
      const id = (b.id ?? b.key) as AnyNode | null | undefined;
      if (id?.type === 'Identifier') node.name = id.name as string;
      break;
    }
    case 'Import':
      node.value = (b.source as AnyNode).value as string;
      break;
  }

  // Initialized declarations (`const x = req.body`) are assignments for analysis purposes.
  if (b.type === 'VariableDeclarator' && b.init) {
    node.type = 'Assignment';
    node.left = one('id');
    node.right = one('init');
    node.operator = '=';
    node.name = pathOf(b.id as AnyNode);
  }
}
