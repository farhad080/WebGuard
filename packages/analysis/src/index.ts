// Profiler
export {
  ProfilerService,
  DEFAULT_IGNORED_DIRS,
  fileFromStartScript,
  type ProfilerOptions,
  type InventoryFile,
  type ProjectInventory,
} from './profiler/profiler.js';

// Project Overview statistics
export { countLoc, countLines, emptyLoc, addLoc } from './stats/loc.js';
export {
  buildProjectStats,
  buildTree,
  dependencyStatsOf,
  dependencyCountsOf,
  analysisDepthOf,
  DEFAULT_TREE_LIMITS,
  type ProjectStatsInput,
  type StatsFinding,
  type StatsRollup,
  type DependencyCounts,
  type ExtractionFacts,
  type TreeLimits,
} from './stats/project-stats.js';
export { ignoredDirOf } from './profiler/ignored-dirs.js';
export { BINARY_EXTENSIONS, detectLanguage, CODE_LANGUAGES } from './profiler/languages.js';

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
export { sensitiveFileExposure } from './detection/detectors/a7-sensitive-file-exposure.js';
export {
  vulnerableDependencies,
  createDependencyDetector,
  type DependencyDetectorOptions,
} from './detection/detectors/a11-vulnerable-deps.js';
export { securityMisconfig } from './detection/detectors/a12-security-misconfig.js';
export { INFORMATIONAL_NOTES } from './detection/informational.js';

// Dependencies & advisories
export {
  SnapshotAdvisorySource,
  OsvAdvisorySource,
  type AdvisorySource,
  type Advisory,
  type AdvisoryMatch,
  type AdvisoryResult,
  type PackageRef,
  type OsvSourceOptions,
} from './deps/advisories.js';
export { ADVISORY_SNAPSHOT, SNAPSHOT_META } from './deps/advisory-snapshot.js';
export { collectDependencies, editDistance, type ResolvedDependency } from './deps/dependencies.js';
export { POPULAR_PACKAGES, TYPOSQUAT_ALLOWLIST } from './deps/popular-packages.js';

// Remediation
export {
  RemediationService,
  TEMPLATE_DETECTOR_IDS,
  type RemediationOptions,
} from './remediation/service.js';
export { TEMPLATE_SETS } from './remediation/templates.js';
export { REFS as REMEDIATION_REFERENCES } from './remediation/references.js';
export type {
  FixTemplate,
  TemplateSet,
  ContextInput,
  ContextualExample,
  RemediationLlmProvider,
} from './remediation/types.js';
export type { EnrichedFinding } from './detection/types.js';
