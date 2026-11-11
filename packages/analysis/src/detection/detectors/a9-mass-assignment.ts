import { findAll, matchesName, textOf, walk } from '../../ast/queries.js';
import { resolveValues, traceTaint, type TaintTrace } from '../../ast/taint.js';
import type { AstNode, ParsedFile } from '../../ast/types.js';
import { getRouteTable } from '../../routes/route-table.js';
import { registerDetector } from '../registry.js';
import type { DetectionContext, RawFinding } from '../types.js';
import {
  describeFlow,
  findingAt,
  isModelish,
  parsedFiles,
  propertyKey,
  unwrapAwait,
} from './shared.js';

/**
 * A9 — Mass assignment / over-selection (AST + dataflow).
 *
 *  1. Mass assignment: the whole request body (`req.body`, `{ ...req.body }`,
 *     `Object.assign({}, req.body)`) is written to a model via `create/update/upsert/insert…`
 *     or merged into a model instance (`Object.assign(user, req.body)`), with no field
 *     allowlist. Confidence 0.85 (high) when the model definition has privileged fields the
 *     client can then set (role, isAdmin, UserId, price, …); 0.55 (medium) otherwise.
 *     Juice Shop #23 (feedback posted with someone else's UserId), #30 (client-controlled fields).
 *  2. Over-selection: the attributes/fields/projection of a query come from the client
 *     (`attributes: req.query.fields.split(',')`), so sensitive columns such as the password
 *     hash can be requested. 0.8 when the model has sensitive fields, 0.6 otherwise.
 *     Juice Shop #13.
 *
 * Suppressed: bodies filtered by an allowlist (`pick(req.body, [...])`, explicit fields),
 * bodies validated upstream (validation middleware such as celebrate / zod / joi /
 * express-validator on the route, or `schema.parse/validate(req.body)` in the handler), and
 * Nest `@Body()` DTO parameters (validated by ValidationPipe).
 */

const CATEGORY = 'A01:2025-Broken Access Control' as const;

const WRITE_METHODS = new Set([
  'create', 'build', 'bulkCreate', 'update', 'upsert', 'insert', 'insertOne', 'insertMany',
  'updateOne', 'updateMany', 'findOneAndUpdate', 'findByIdAndUpdate', 'replaceOne', 'set',
]); // prettier-ignore
const SELECTOR_FIRST = new Set([
  'update',
  'updateOne',
  'updateMany',
  'findOneAndUpdate',
  'findByIdAndUpdate',
  'replaceOne',
]);
const MERGE_CALLS = [
  'Object.assign',
  '_.assign',
  '_.merge',
  '_.extend',
  'lodash.merge',
  'merge',
  'extend',
];
const WHOLE_REQUEST = /^(req|request)\.(body|query)$|^ctx\.request\.body$/;

const PRIVILEGED =
  /^(role|roles|isAdmin|admin|is_admin|isStaff|permissions?|privileges?|accessLevel|UserId|userId|ownerId|price|balance|credit|walletBalance|discount|deluxeToken|totpSecret|isVerified|emailVerified|approved|isActive)$/;
const SENSITIVE =
  /^(password|passwordHash|hash|salt|token|secret|totpSecret|apiKey|deluxeToken|resetToken|refreshToken)$/i;
const VALIDATION_MW = /validat|celebrate|zod|joi|yup|schema|checkSchema|express-validator|body\(/i;
const VALIDATION_IN_HANDLER =
  /\.(parse|safeParse|validate|validateAsync|validateSync|assert)\(\s*req\.body|validationResult\(\s*req\s*\)|matchedData\(\s*req/;
const SELECTION_KEYS = new Set(['attributes', 'select', 'projection', 'fields']);

const EXPLAIN = {
  mass:
    'The whole client-supplied request body is written to a database model with no field ' +
    'allowlist (mass assignment). Any column the model has can be set by adding it to the ' +
    'JSON, e.g. {"role": "admin"} to escalate privileges or {"UserId": 2} to act as another ' +
    'user. Client-side forms and validation do not prevent this: attackers call the API directly.',
  select:
    'The client decides which columns are returned (over-selection). Requesting fields such ' +
    'as password or totpSecret leaks data the endpoint was never meant to expose, e.g. ' +
    'password hashes of other users.',
};
const FIX = {
  mass:
    'Copy only the fields the client may set (an explicit allowlist / DTO, e.g. ' +
    "pick(req.body, ['email', 'password'])), or validate the body with a strict schema " +
    '(zod/joi with unknown keys rejected); set privileged fields (role, UserId) on the server.',
  select:
    'Use a fixed server-side attribute list (or validate requested fields against an allowlist) ' +
    'and always exclude secrets such as password hashes.',
};

/** Model name → field names, from Sequelize define/init, class declarations, Mongoose schemas. */
function modelFields(files: ParsedFile[]): Map<string, Set<string>> {
  const models = new Map<string, Set<string>>();
  const add = (name: string | undefined, keys: Iterable<string>) => {
    if (!name) return;
    const key = normalizeModel(name);
    const set = models.get(key) ?? new Set<string>();
    for (const k of keys) set.add(k);
    models.set(key, set);
  };
  const keysOf = (obj: AstNode | undefined) =>
    obj?.type === 'Object'
      ? obj.children.filter((p) => p.type === 'Property').map((p) => propertyKey(p) ?? '')
      : [];

  for (const file of files) {
    for (const n of walk(file)) {
      if (n.type === 'Call') {
        const args = n.arguments ?? [];
        if (matchesName(n.name, '*.define') && args[0]?.type === 'StringLiteral')
          add(args[0].value, keysOf(args[1]));
        else if (n.callee?.property === 'init' && n.callee.object?.type === 'Identifier')
          add(n.callee.object.name, keysOf(args[0]));
        else if (
          (n.name === 'Schema' || matchesName(n.name, '*.Schema')) &&
          n.parent?.type === 'Assignment'
        ) {
          add(n.parent.name?.replace(/Schema$/i, ''), keysOf(args[0]));
        }
      } else if (n.rawType === 'ClassDeclaration') {
        const name = (n.raw as { id?: { name?: string } }).id?.name;
        const props = walk(n);
        const keys: string[] = [];
        for (const p of props) {
          if (p.rawType === 'ClassProperty' && p.parent?.parent === n)
            keys.push(propertyKey(p) ?? '');
        }
        if (keys.length > 0) add(name, keys);
      }
    }
  }
  return models;
}

function normalizeModel(name: string): string {
  return name
    .split('.')
    .at(-1)!
    .replace(/(Model|Repository|Repo|Collection|Entity)$/i, '')
    .replace(/s$/i, '')
    .toLowerCase();
}

/** Model a receiver refers to, following `const product = await ProductModel.findByPk(...)`. */
function modelNameOf(receiver: AstNode | undefined): string | undefined {
  if (!receiver) return undefined;
  if (receiver.type === 'Identifier') {
    for (const v of resolveValues(receiver)) {
      const value = unwrapAwait(v);
      if (value !== receiver && value.type === 'Call' && value.callee?.type === 'MemberAccess') {
        return modelNameOf(value.callee.object);
      }
    }
  }
  return receiver.name ? normalizeModel(receiver.name) : undefined;
}

function wholeRequestFlow(trace: TaintTrace) {
  return trace.flows.find((f) => WHOLE_REQUEST.test(f.source.name ?? '') && !f.throughCall);
}

/** `req.body`, `{ ...req.body }`, `Object.assign({}, req.body)`, a variable holding one of those. */
function wholeBody(arg: AstNode): { trace: TaintTrace; via: AstNode } | undefined {
  for (const v of resolveValues(arg)) {
    const value = unwrapAwait(v);
    if (value.type === 'Call' && MERGE_CALLS.some((p) => matchesName(value.name, p))) {
      for (const a of value.arguments ?? []) {
        const inner = wholeBody(a);
        if (inner) return inner;
      }
      continue;
    }
    if (value.type === 'Object') {
      // Only spreads carry the whole body; explicit `key: req.body.key` is an allowlist.
      for (const spread of value.children.filter((c) => c.rawType === 'SpreadElement')) {
        const trace = traceTaint(spread);
        if (wholeRequestFlow(trace)) return { trace, via: spread };
      }
      continue;
    }
    const trace = traceTaint(value);
    if (wholeRequestFlow(trace)) return { trace, via: value };
  }
  return undefined;
}

function validatedUpstream(ctx: DetectionContext, file: ParsedFile, call: AstNode): boolean {
  for (let p = call.parent; p; p = p.parent) {
    if (p.type === 'Function' && VALIDATION_IN_HANDLER.test(textOf(file, p))) return true;
  }
  return getRouteTable(ctx).routes.some(
    (r) =>
      r.handlerNode !== undefined &&
      r.handlerFile === file &&
      r.handlerNode.loc.startLine <= call.loc.startLine &&
      r.handlerNode.loc.endLine >= call.loc.endLine &&
      r.middlewareChain.some((m) => VALIDATION_MW.test(m.name)),
  );
}

export const massAssignment = registerDetector({
  id: 'A9-mass-assignment',
  title: 'Mass assignment / over-selection',
  owaspCategory: CATEGORY,
  cwe: 'CWE-915',
  technique: 'dataflow',
  explanation: EXPLAIN.mass,
  fixSuggestion: FIX.mass,

  run(ctx) {
    const files = parsedFiles(ctx);
    const models = modelFields(files);
    const findings: RawFinding[] = [];

    for (const file of files) {
      for (const call of findAll(file, (n) => n.type === 'Call')) {
        const args = call.arguments ?? [];
        const callee = call.callee;
        const method = callee?.type === 'MemberAccess' ? (callee.property ?? '') : '';

        // ---- Mass assignment ----
        let candidates: AstNode[] = [];
        let target: AstNode | undefined;
        if (WRITE_METHODS.has(method) && isModelish(callee?.object)) {
          target = callee?.object;
          if (SELECTOR_FIRST.has(method) && args.length >= 2) {
            const optionsHaveWhere =
              args[1]?.type === 'Object' &&
              args[1].children.some((p) => propertyKey(p) === 'where');
            candidates = optionsHaveWhere ? [args[0]!] : [args[1]!];
          } else {
            candidates = args.slice(0, 1);
          }
        } else if (
          MERGE_CALLS.some((p) => matchesName(call.name, p)) &&
          args[0] &&
          args[0].type !== 'Object' &&
          isModelish(args[0])
        ) {
          // Object.assign(user, req.body) on a model instance
          target = args[0];
          candidates = args.slice(1);
        }
        for (const candidate of candidates) {
          const whole = wholeBody(candidate);
          if (!whole || validatedUpstream(ctx, file, call)) continue;
          const modelName = modelNameOf(target);
          const fields = modelName ? models.get(modelName) : undefined;
          const privileged = fields ? [...fields].filter((f) => PRIVILEGED.test(f)) : [];
          const flow = whole.trace.flows.find((f) => WHOLE_REQUEST.test(f.source.name ?? ''))!;
          const what = `${call.name ?? method}()`;
          findings.push(
            findingAt(ctx, file, call, {
              detectorId: 'A9-mass-assignment',
              owaspCategory: CATEGORY,
              severity: 'high',
              confidence: privileged.length > 0 ? 0.85 : 0.55,
              evidence:
                `${what} writes the whole request body ${describeFlow(file, whole.via, flow)} with no field allowlist` +
                (privileged.length > 0
                  ? `; the ${modelName} model has privileged field(s) ${privileged.join(', ')} that the client can set`
                  : fields
                    ? `; no privileged fields were found on the ${modelName} model, so impact depends on its columns`
                    : '; the model definition was not found, so impact depends on its columns'),
              cwe: 'CWE-915',
            }),
          );
          break;
        }

        // ---- Over-selection: client-chosen attributes / projection ----
        const selections: AstNode[] = [];
        if ((method === 'select' || method === 'projection') && args[0]) selections.push(args[0]);
        for (const arg of args) {
          for (const v of resolveValues(arg)) {
            if (v.type !== 'Object') continue;
            for (const p of v.children) {
              if (
                p.type === 'Property' &&
                SELECTION_KEYS.has(propertyKey(p) ?? '') &&
                p.children.at(-1)
              ) {
                selections.push(p.children.at(-1)!);
              }
            }
          }
        }
        for (const sel of selections) {
          const trace = traceTaint(sel);
          const flow = trace.flows[0];
          if (!flow) continue;
          const receiver = callee?.type === 'MemberAccess' ? callee.object : undefined;
          const modelName = modelNameOf(receiver);
          const sensitive = modelName
            ? [...(models.get(modelName) ?? [])].filter((f) => SENSITIVE.test(f))
            : [];
          findings.push(
            findingAt(ctx, file, call, {
              detectorId: 'A9-mass-assignment',
              owaspCategory: CATEGORY,
              severity: 'high',
              confidence: sensitive.length > 0 ? 0.8 : 0.6,
              evidence:
                `the selected fields of ${call.name}() come from the client: ${describeFlow(file, sel, flow)}` +
                (sensitive.length > 0
                  ? `; the ${modelName} model has sensitive field(s) ${sensitive.join(', ')} that can be requested`
                  : ''),
              explanation: EXPLAIN.select,
              fixSuggestion: FIX.select,
              cwe: 'CWE-213',
            }),
          );
          break;
        }
      }
    }
    return findings;
  },
});
