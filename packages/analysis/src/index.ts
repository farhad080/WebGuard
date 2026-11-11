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

// Detection engine
export {
  TECHNIQUE_STAGES,
  type Technique,
  type Detector,
  type DetectionContext,
  type RawFinding,
  type ValidatedFinding,
  type FindingDraft,
  type DetectorError,
} from './detection/types.js';
export { createDetectionContext, type DetectionContextInput } from './detection/context.js';
export { DetectorRegistry, builtinDetectors, registerDetector } from './detection/registry.js';
export {
  DetectionEngine,
  type EngineOptions,
  type EngineResult,
  type EngineLogger,
} from './detection/engine.js';
export { dedupeFindings } from './detection/dedupe.js';
export {
  SEVERITIES,
  isSeverity,
  severityRank,
  compareSeverity,
  maxSeverity,
  confidenceBand,
  clampConfidence,
  combineConfidence,
  filterByConfidence,
  countFindings,
  type ConfidenceBand,
  type FindingCounts,
} from './detection/scoring.js';
export { getSnippet, type SnippetOptions } from './detection/snippet.js';
export { createDefaultDetectorRegistry } from './detection/detectors/index.js';
export { exampleTodoComment } from './detection/detectors/example-todo-comment.js';
export { sqlInjection } from './detection/detectors/a1-sql-injection.js';
export { nosqlInjection } from './detection/detectors/a2-nosql-injection.js';
export { ssti } from './detection/detectors/a3-ssti.js';
export { xss } from './detection/detectors/a4-xss.js';
export {
  hardcodedSecrets,
  createSecretsDetector,
  isPlaceholder,
  shannonEntropy,
  type SecretsDetectorOptions,
} from './detection/detectors/a5-hardcoded-secrets.js';
export { weakCrypto } from './detection/detectors/a6-weak-crypto.js';

// Taint tracing
export {
  traceTaint,
  resolveIdentifier,
  resolveValues,
  scopeChain,
  parameterNames,
  stringParts,
  interpolatedParts,
  isStringBuilding,
  isHttpSource,
  sourcesWithin,
  type TaintOptions,
  type TaintTrace,
  type TaintFlow,
  type Resolution,
} from './ast/taint.js';
export { brokenAccessControl } from './detection/detectors/a8-access-control.js';
export { massAssignment } from './detection/detectors/a9-mass-assignment.js';
export { missingCsrf } from './detection/detectors/a10-missing-csrf.js';

// Route model
export {
  buildRouteTable,
  getRouteTable,
  isStateChanging,
  type RouteTable,
  type RouteEntry,
  type Middleware,
  type HttpMethod,
  type AuthMechanism,
} from './routes/route-table.js';
