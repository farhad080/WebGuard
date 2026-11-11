// Profiler
export {
  ProfilerService,
  DEFAULT_IGNORED_DIRS,
  type ProfilerOptions,
} from './profiler/profiler.js';
export { detectLanguage, CODE_LANGUAGES } from './profiler/languages.js';

// Common AST contract
export type {
  AstNode,
  NodeTag,
  NodeType,
  ParsedFile,
  ParseError,
  SourceLocation,
} from './ast/types.js';
export { LineIndex } from './ast/line-index.js';
export {
  walk,
  findAll,
  findCalls,
  findAssignments,
  findStringLiterals,
  findMemberWrites,
  findTagged,
  findAncestor,
  hasTag,
  containsSource,
  matchesName,
  textOf,
  type AssignmentQuery,
  type QueryRoot,
} from './ast/queries.js';
export { applyTags, DEFAULT_TAG_RULES, type TagRule } from './ast/tagging.js';

// Parser layer
export {
  ParserRegistry,
  type ParserAdapter,
  type ParseInput,
  type AdapterResult,
  type ParserRegistryOptions,
} from './parsers/registry.js';
export { BabelJsTsAdapter } from './parsers/babel-adapter.js';
export { createDefaultParserRegistry, parseSourceFiles } from './parse-project.js';
