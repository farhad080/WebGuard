import type { Language } from '@webguard/core';
import type { LineIndex } from './line-index.js';

/**
 * Language-independent AST contract shared by every parser adapter and detector.
 *
 * Adapters map their native trees onto this small vocabulary; anything without a common
 * meaning becomes `Other` (its native type is kept in `rawType`, and the native node in `raw`).
 */
export type NodeType =
  | 'Program'
  | 'Function'
  | 'Call'
  | 'MemberAccess'
  | 'Assignment'
  | 'Identifier'
  | 'StringLiteral'
  | 'TemplateLiteral'
  | 'Literal'
  | 'Binary'
  | 'Object'
  | 'Array'
  | 'Property'
  | 'Import'
  | 'Return'
  | 'Block'
  | 'Other';

/** Lines are 1-based; columns are 0-based (ESTree convention). End is exclusive. */
export interface SourceLocation {
  startLine: number;
  startCol: number;
  endLine: number;
  endCol: number;
}

/** Well-known tags. Detectors may add their own (`source:*`, `sink:*`). */
export type NodeTag =
  | 'source:http-input'
  | 'source:user-profile'
  | 'source:client-url'
  | 'sink:dom-html'
  | 'sink:code-exec'
  | 'sink:command-exec'
  | (string & {});

export interface AstNode {
  /** Normalized, language-independent type. */
  type: NodeType;
  /** The adapter's native node type, e.g. Babel's `OptionalCallExpression`. */
  rawType: string;
  loc: SourceLocation;
  /** All child nodes, in source order. */
  children: AstNode[];
  /** Set by tagging passes (see `tagging.ts`). */
  tags: NodeTag[];

  /**
   * Dotted name, when statically known:
   * Identifier → `req`; MemberAccess → `req.body.name`; Call → callee path (`db.query`);
   * Function → its name. Unknown parts appear as `?` (e.g. `getDb().query` → `?.query`).
   */
  name?: string;
  /** StringLiteral value; TemplateLiteral static text (only when it has no expressions). */
  value?: string;
  /** Assignment / Binary operator, e.g. `=`, `+=`, `+`. */
  operator?: string;

  /** Call */
  callee?: AstNode;
  arguments?: AstNode[];
  /** MemberAccess */
  object?: AstNode;
  property?: string;
  computed?: boolean;
  /** Assignment (incl. initialized variable declarations) and Binary */
  left?: AstNode;
  right?: AstNode;

  /** Parent node (non-enumerable, so nodes stay JSON-serializable). */
  readonly parent?: AstNode;
  /** Escape hatch: the adapter's native node (non-enumerable). */
  readonly raw?: unknown;
}

export interface ParseError {
  message: string;
  line?: number;
  column?: number;
  /** True when the parser recovered and still produced an AST. */
  recovered: boolean;
}

export interface ParsedFile {
  /** Project-relative, `/`-separated. */
  path: string;
  language: Language;
  /** Null when the file could not be parsed at all. */
  ast: AstNode | null;
  sourceText: string;
  lineIndex: LineIndex;
  parseError?: ParseError;
}
