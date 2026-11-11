import { findAll } from '../../ast/queries.js';
import { resolveValues, traceTaint, type TaintTrace } from '../../ast/taint.js';
import type { AstNode } from '../../ast/types.js';
import { registerDetector } from '../registry.js';
import type { RawFinding } from '../types.js';
import { bestFlow, describeFlow, findingAt, parsedFiles } from './shared.js';

/**
 * A2 — NoSQL injection (dataflow).
 *
 * Objective: find MongoDB-style queries whose selector (or `$where` JavaScript) is controlled
 * by the client.
 *
 * Logic, for collection/model calls (`find`, `findOne`, `update*`, `remove`, `delete*`,
 * `count*`, `mapReduce`, `$where`):
 *  1. Request object as selector: `coll.find(req.body)` / `update(req.query, …)`. The client
 *     controls the whole query, operators included (`{"email": {"$ne": null}}`).
 *  2. Uncoerced selector field: `{ _id: req.body.id }`. JSON bodies and `qs`-parsed query
 *     strings can carry objects, so `{"id": {"$ne": -1}}` matches *every* document (with
 *     `update(..., { multi: true })`, it modifies all of them).
 *  3. `$where` / `mapReduce` with tainted strings: server-side JavaScript injection.
 *
 * Confidence: 0.6 (medium) for operator injection, because exploitability depends on how the
 * body is parsed and on the field's type. 0.8 (high) for `$where` with direct taint (the
 * string is executed as JS). Through an unknown call: 0.5.
 *
 * False positives suppressed: scalar-coerced values (`String(id)`, `Number(id)`, `` `${id}` ``,
 * `id + ''`), route params (`req.params.*` are always strings, so they can't carry operators,
 * but they still count for `$where`), `Array.prototype.find(fn)`, and non-collection receivers.
 */

const NOSQL_METHODS = new Set([
  'find', 'findOne', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndRemove', 'findOneAndReplace',
  'update', 'updateOne', 'updateMany', 'replaceOne', 'remove', 'deleteOne', 'deleteMany',
  'count', 'countDocuments', 'exists', 'distinct',
]); // prettier-ignore
const UPDATE_METHODS = /^(update|updateOne|updateMany|replaceOne|findOneAnd.*|remove|delete.*)$/;
const COLLECTION_RECEIVER =
  /(^|\.)db\.|collection|Collection$|Model$|Repository$|^this\.(db|model|collection)\b/;

const CATEGORY = 'A05:2025-Injection' as const;

function isCollectionReceiver(receiver: AstNode | undefined): boolean {
  const name = receiver?.name ?? '';
  const last = name.split('.').at(-1) ?? '';
  // `db.users`, `reviewsCollection`, `UserModel`, or a Mongoose model like `User`.
  return COLLECTION_RECEIVER.test(name) || /^[A-Z][A-Za-z0-9]*$/.test(last);
}

const isRouteParam = (n: AstNode) => /^(req|request|ctx)\.params(\.|$)/.test(n.name ?? '');

function propertyKey(prop: AstNode): string | undefined {
  const key = (prop.raw as { key?: { type: string; name?: string; value?: string } }).key;
  return key?.type === 'Identifier' ? key.name : key?.value;
}

export const nosqlInjection = registerDetector({
  id: 'A2-nosql-injection',
  title: 'NoSQL injection',
  owaspCategory: CATEGORY,
  cwe: 'CWE-943',
  technique: 'dataflow',
  explanation:
    'A database query selector is built from client-supplied data without forcing it to a ' +
    'plain value. MongoDB treats objects in a selector as operators, so a request like ' +
    '{"id": {"$ne": -1}} turns "find this one review" into "match every document". That can ' +
    'bypass logins or update/delete every record. `$where` goes further: it executes ' +
    'the string as JavaScript on the database server.',
  fixSuggestion:
    'Cast selector values to the expected scalar type (String(id), Number(id), or a validated ' +
    'ObjectId) or validate the body shape with a schema. Never pass req.body/req.query as a ' +
    'selector, and avoid $where; use regular query operators instead.',

  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of parsedFiles(ctx)) {
      for (const call of findAll(file, (n) => n.type === 'Call')) {
        const callee = call.callee;
        if (callee?.type !== 'MemberAccess' || !callee.property) continue;
        const method = callee.property;
        const report = (
          node: AstNode,
          trace: TaintTrace,
          kind: 'selector' | 'field' | 'where',
          what: string,
        ) => {
          const flow = bestFlow(trace)!;
          const direct = trace.direct;
          const confidence = kind === 'where' ? (direct ? 0.8 : 0.5) : direct ? 0.6 : 0.5;
          const isUpdate = UPDATE_METHODS.test(method);
          findings.push(
            findingAt(ctx, file, call, {
              detectorId: 'A2-nosql-injection',
              owaspCategory: CATEGORY,
              severity: kind === 'where' ? 'critical' : 'high',
              confidence,
              evidence:
                kind === 'where'
                  ? `Request input ${describeFlow(file, node, flow)} reaches ${what}, which MongoDB executes as JavaScript`
                  : `Client-supplied ${describeFlow(file, node, flow)} is used as ${what} in ${call.name}() without type coercion${isUpdate ? ' (a crafted operator can update/delete many documents)' : ''}`,
            }),
          );
        };

        // `query.$where(str)` / `coll.mapReduce(mapFn, reduceFn)` with strings.
        if (method === '$where' || method === 'mapReduce') {
          for (const arg of call.arguments ?? []) {
            const trace = traceTaint(arg);
            if (trace.tainted) {
              report(arg, trace, 'where', method === '$where' ? '$where' : 'mapReduce');
              break;
            }
          }
          continue;
        }

        if (!NOSQL_METHODS.has(method) || !isCollectionReceiver(callee.object)) continue;
        // Sequelize `Model.update(values, { where })`: the first argument is values, not a selector.
        const second = call.arguments?.[1];
        if (
          second?.type === 'Object' &&
          second.children.some(
            (p) =>
              p.type === 'Property' && (p.raw as { key?: { name?: string } }).key?.name === 'where',
          )
        ) {
          continue;
        }
        const selectorArg = call.arguments?.[0];
        if (!selectorArg || selectorArg.type === 'Function') continue; // Array#find(fn)

        let reported = false;
        for (const selector of resolveValues(selectorArg)) {
          if (reported) break;
          // `{ where: {...} }` is SQL-ORM options (Sequelize/TypeORM), not a Mongo selector:
          // those bind values and use Symbol operators, so JSON objects can't inject.
          if (
            selector.type === 'Object' &&
            selector.children.some(
              (p) =>
                p.type === 'Property' &&
                (p.raw as { key?: { name?: string } }).key?.name === 'where',
            )
          ) {
            continue;
          }
          if (selector.type === 'Object') {
            for (const prop of selector.children) {
              if (prop.type !== 'Property') continue;
              const key = propertyKey(prop);
              const value = prop.children.at(-1);
              if (!value) continue;
              if (key === '$where') {
                const trace = traceTaint(value);
                if (trace.tainted) {
                  report(value, trace, 'where', '$where');
                  reported = true;
                  break;
                }
                continue;
              }
              const trace = traceTaint(value, { coercionSanitizes: true });
              if (trace.tainted && !trace.flows.every((f) => isRouteParam(f.source))) {
                report(value, trace, 'field', `the "${key ?? '?'}" selector`);
                reported = true;
                break;
              }
            }
          } else {
            const trace = traceTaint(selector, { coercionSanitizes: true });
            if (trace.tainted && !trace.flows.every((f) => isRouteParam(f.source))) {
              report(selector, trace, 'selector', 'the entire query selector');
              reported = true;
            }
          }
        }
      }
    }
    return findings;
  },
});
