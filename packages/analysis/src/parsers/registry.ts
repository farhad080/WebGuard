import type { Language } from '@webguard/core';
import { LineIndex } from '../ast/line-index.js';
import { applyTags, DEFAULT_TAG_RULES, type TagRule } from '../ast/tagging.js';
import type { AstNode, ParseError, ParsedFile } from '../ast/types.js';

export interface ParseInput {
  path: string;
  language: Language;
  sourceText: string;
}

export interface AdapterResult {
  ast: AstNode | null;
  parseError?: ParseError;
}

/**
 * Turns source text of one or more languages into the common AST.
 * To support a new language, implement this and register it; nothing else changes.
 */
export interface ParserAdapter {
  readonly id: string;
  readonly languages: readonly Language[];
  /** May throw; the registry converts any exception into a non-fatal parseError. */
  parse(input: ParseInput): AdapterResult;
}

export interface ParserRegistryOptions {
  /** Tag rules applied to every AST after parsing (default: DEFAULT_TAG_RULES). */
  tagRules?: readonly TagRule[];
}

export class ParserRegistry {
  private readonly adapters = new Map<Language, ParserAdapter>();
  private readonly tagRules: readonly TagRule[];

  constructor(options: ParserRegistryOptions = {}) {
    this.tagRules = options.tagRules ?? DEFAULT_TAG_RULES;
  }

  register(adapter: ParserAdapter): this {
    for (const language of adapter.languages) {
      const existing = this.adapters.get(language);
      if (existing) {
        throw new Error(`Language "${language}" is already handled by adapter "${existing.id}"`);
      }
      this.adapters.set(language, adapter);
    }
    return this;
  }

  supports(language: Language): boolean {
    return this.adapters.has(language);
  }

  get supportedLanguages(): Language[] {
    return [...this.adapters.keys()];
  }

  /**
   * Parses one file. Never throws for bad input: unsupported languages and adapter failures
   * come back as a ParsedFile with `ast: null` and a `parseError`.
   */
  parse(input: ParseInput): ParsedFile {
    const base = {
      path: input.path,
      language: input.language,
      sourceText: input.sourceText,
      lineIndex: new LineIndex(input.sourceText),
    };
    const adapter = this.adapters.get(input.language);
    if (!adapter) {
      return {
        ...base,
        ast: null,
        parseError: { message: `No parser for language "${input.language}"`, recovered: false },
      };
    }
    try {
      const result = adapter.parse(input);
      applyTags(result.ast, this.tagRules);
      return { ...base, ast: result.ast, parseError: result.parseError };
    } catch (err) {
      return {
        ...base,
        ast: null,
        parseError: {
          message: err instanceof Error ? err.message : String(err),
          recovered: false,
        },
      };
    }
  }
}
