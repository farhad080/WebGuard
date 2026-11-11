import { textOf, walk } from '../../ast/queries.js';
import { resolveIdentifier, resolveValues, traceTaint } from '../../ast/taint.js';
import type { AstNode, ParsedFile } from '../../ast/types.js';
import { getRouteTable, type RouteEntry } from '../../routes/route-table.js';
import { registerDetector } from '../registry.js';
import type { DetectionContext, RawFinding } from '../types.js';
import { isModelish, propertyKey, shorten } from './shared.js';

/**
 * A8 — Broken access control / IDOR (AST + dataflow over the RouteTable).
 *
 * Authorization intent is semantic, so every finding is a **candidate** at medium confidence
 * ("confirm manually"), severity high.
 *
 *  1. Missing authorization on sensitive routes: PUT/PATCH/DELETE routes, and admin /
 *     accounting / configuration routes, with no authentication middleware and no auth check
 *     in the handler (0.6). An admin-ish route that is authenticated but has no role check
 *     gets 0.5. If the front end guards a matching route (`canActivate`), the evidence says
 *     "guarded only client-side". Juice Shop #20 (admin section), #22 (deleting feedback).
 *  2. IDOR: inside a route handler, a lookup or mutation (`findByPk`, `findOne`, `update`,
 *     `destroy`, …) keyed by a client-supplied id (`req.params/query/body`, Nest `@Param`)
 *     with no ownership predicate (`UserId: req.user.id`) and no ownership comparison
 *     afterwards. Also a create/update that sets a client-supplied foreign key of an owned
 *     resource (`BasketId: req.body.BasketId`). Juice Shop #21 (view another basket),
 *     #24 (manipulate basket).
 *
 * Routes protected by a role/permission middleware are not checked for IDOR (admins may act
 * on any record).
 */

const CATEGORY = 'A01:2025-Broken Access Control' as const;

const KEY_LOOKUPS = new Set([
  'findByPk',
  'findById',
  'findByIdAndUpdate',
  'findByIdAndDelete',
  'findByIdAndRemove',
]);
const WHERE_LOOKUPS = new Set([
  'findOne', 'findAll', 'findOneBy', 'findBy', 'update', 'destroy', 'delete', 'deleteOne',
  'deleteMany', 'updateOne', 'updateMany', 'findOneAndUpdate', 'findOneAndDelete',
  'findOneAndRemove', 'remove', 'count',
]); // prettier-ignore
const WRITES = new Set([
  'create',
  'build',
  'bulkCreate',
  'update',
  'upsert',
  'insert',
  'insertOne',
  'save',
]);

const CLIENT_INPUT = /^(req|request|ctx)\.(params|query|body)(\.|$)/;
const ID_KEY = /^(id|_id|[A-Za-z]+Id)$/;
const OWNER_KEY =
  /^(UserId|userId|user_id|ownerId|owner|createdBy|AccountId|accountId|CustomerId|customerId)$/;
const OWNED_FK =
  /^(Basket|Order|Card|Address|Wallet|Account|Payment|Cart|Invoice|Profile|Delivery|Document|Message)Id$/i;
const IDENTITY_TEXT =
  /req\.(user|session|auth)\b|res\.locals\.(user|auth)|currentUser|loggedInUser|authenticatedUser|authUser|session\.user|authenticatedUsers/;
const OWNERSHIP_CHECK =
  /(UserId|userId|ownerId|owner|createdBy)\b[^;\n]{0,80}(===|!==|==|!=)[^;\n]{0,80}(req\.(user|session|auth)|loggedInUser|currentUser|authenticatedUser)|(req\.(user|session|auth)|loggedInUser|currentUser|authenticatedUser)[^;\n]{0,80}(===|!==|==|!=)[^;\n]{0,80}(UserId|userId|ownerId|owner)/;
const SENSITIVE_PATH =
  /admin|administration|accounting|config(uration)?|metrics|roles?\b|permissions?|privileges?/i;

const EXPLAIN = {
  route:
    'Candidate (confirm manually): this state-changing or administrative route is reachable ' +
    'without any server-side authentication/authorization check. Hiding a button or guarding ' +
    "the page in the front end (e.g. Angular canActivate) doesn't protect the API: anyone can " +
    "call it directly with curl, e.g. deleting other users' feedback or reading admin data.",
  idor:
    'Candidate (confirm manually): the handler loads or modifies a record by an id the client ' +
    'chooses, without checking that the record belongs to the logged-in user (an insecure direct ' +
    'object reference). Changing the id in the URL or body (e.g. /rest/basket/2) exposes or ' +
    "alters other users' data.",
};
const FIX = {
  route:
    'Enforce authorization on the server: add authentication plus a role/permission check ' +
    '(e.g. isAdmin()) to the route; never rely on client-side route guards.',
  idor:
    'Add an ownership predicate to the query (e.g. where: { id, UserId: req.user.id }) or ' +
    'compare the record owner to the authenticated user before returning or changing it.',
};

/** Nest handler params decorated with @Param / @Query / @Body come from the client. */
function decoratedClientParams(fn: AstNode): Set<string> {
  const params =
    (
      fn.raw as {
        params?: Array<{
          type: string;
          name?: string;
          decorators?: Array<{ expression?: { callee?: { name?: string } } }>;
          parameter?: { name?: string };
        }>;
      }
    ).params ?? [];
  const out = new Set<string>();
  for (const p of params) {
    const names = (p.decorators ?? []).map((d) => d.expression?.callee?.name);
    if (names.some((n) => n === 'Param' || n === 'Query' || n === 'Body') && p.name)
      out.add(p.name);
  }
  return out;
}

function clientSource(handler: AstNode) {
  const nestParams = decoratedClientParams(handler);
  return (n: AstNode): boolean =>
    (n.tags.includes('source:http-input') && CLIENT_INPUT.test(n.name ?? '')) ||
    (n.type === 'Identifier' &&
      nestParams.has(n.name ?? '') &&
      resolveIdentifier(n).kind === 'parameter');
}

/** The `where` object of a Sequelize/TypeORM options arg, or a Mongo-style selector. */
function whereObjects(call: AstNode): AstNode[] {
  const out: AstNode[] = [];
  for (const arg of call.arguments ?? []) {
    for (const v of resolveValues(arg)) {
      if (v.type !== 'Object') continue;
      const where = v.children.find((p) => p.type === 'Property' && propertyKey(p) === 'where');
      const whereValue = where?.children.at(-1);
      if (whereValue?.type === 'Object') out.push(whereValue);
      else if (!where && call.arguments?.[0] === arg) out.push(v); // Mongo selector / findOneBy
    }
  }
  return out;
}

function clientGuardedPaths(ctx: DetectionContext): Array<{ path: string; where: string }> {
  const out: Array<{ path: string; where: string }> = [];
  for (const file of ctx.files) {
    if (!file.ast) continue;
    for (const n of walk(file)) {
      if (n.type !== 'Object') continue;
      const keys = new Map(
        n.children.filter((p) => p.type === 'Property').map((p) => [propertyKey(p), p] as const),
      );
      const path = keys.get('path')?.children.at(-1);
      if (path?.type === 'StringLiteral' && keys.has('canActivate')) {
        out.push({ path: path.value ?? '', where: `${file.path}:${n.loc.startLine}` });
      }
    }
  }
  return out;
}

export const brokenAccessControl = registerDetector({
  id: 'A8-broken-access-control',
  title: 'Broken access control / IDOR (candidate)',
  owaspCategory: CATEGORY,
  cwe: 'CWE-862',
  technique: 'dataflow',
  explanation: EXPLAIN.route,
  fixSuggestion: FIX.route,

  run(ctx) {
    const table = getRouteTable(ctx);
    const guarded = clientGuardedPaths(ctx);
    const findings: RawFinding[] = [];
    const seenHandlers = new Set<AstNode>();

    const finding = (
      file: ParsedFile,
      node: AstNode,
      kind: 'route' | 'idor',
      confidence: number,
      evidence: string,
    ): RawFinding => ({
      detectorId: 'A8-broken-access-control',
      owaspCategory: CATEGORY,
      severity: 'high',
      confidence,
      filePath: file.path,
      lineStart: node.loc.startLine,
      lineEnd: node.loc.startLine,
      snippet: ctx.snippet(file.path, node.loc.startLine),
      evidence: `Candidate (${kind === 'route' ? 'missing authorization' : 'missing ownership check'}): ${evidence}`,
      explanation: EXPLAIN[kind],
      fixSuggestion: FIX[kind],
      cwe: kind === 'route' ? 'CWE-862' : 'CWE-639',
    });

    const describe = (r: RouteEntry) => `${r.method} ${r.path}`;
    const chainText = (r: RouteEntry) => {
      const relevant = r.middlewareChain.filter((m) => !m.infrastructure);
      return relevant.length > 0 ? relevant.map((m) => m.name).join(', ') : 'none';
    };

    for (const route of table.routes) {
      // ---- 1. Missing authorization on sensitive routes ----
      const destructive =
        route.method === 'PUT' || route.method === 'PATCH' || route.method === 'DELETE';
      const adminish = SENSITIVE_PATH.test(route.path);
      if (!route.authenticated && (destructive || adminish)) {
        const segment = route.path
          .split('/')
          .filter((s) => s && !s.startsWith(':'))
          .map((s) => s.toLowerCase());
        const client = guarded.find((g) =>
          segment.some((s) => s.length > 3 && g.path.toLowerCase().includes(s.replace(/s$/, ''))),
        );
        findings.push(
          finding(
            route.file,
            route.node,
            'route',
            0.6,
            `${describe(route)} has no authentication or authorization middleware (chain: ${chainText(route)}) and the handler performs no auth check` +
              (client
                ? `; the matching front-end route is guarded only client-side (canActivate at ${client.where})`
                : ''),
          ),
        );
      } else if (
        route.authenticated &&
        !route.hasAuthorization &&
        /admin|administration|accounting/i.test(route.path)
      ) {
        findings.push(
          finding(
            route.file,
            route.node,
            'route',
            0.5,
            `${describe(route)} requires a login (${chainText(route)}) but no role/permission check: any authenticated user can reach it`,
          ),
        );
      }

      // ---- 2. IDOR inside the handler ----
      const handler = route.handlerNode;
      const file = route.handlerFile;
      // IDOR is about an authenticated user reaching others' records: unauthenticated routes are
      // already reported above, and admin/role-guarded routes may legitimately act on any record.
      if (
        !handler ||
        !file ||
        !route.authenticated ||
        route.hasAuthorization ||
        seenHandlers.has(handler)
      ) {
        continue;
      }
      seenHandlers.add(handler);
      const handlerText = textOf(file, handler);
      if (OWNERSHIP_CHECK.test(handlerText)) continue;
      const isClient = clientSource(handler);

      for (const call of walk(handler)) {
        if (call.type !== 'Call' || call.callee?.type !== 'MemberAccess') continue;
        const method = call.callee.property ?? '';
        if (!isModelish(call.callee.object)) continue;
        const model = call.callee.object?.name ?? 'model';
        const args = call.arguments ?? [];

        // findByPk(req.params.id) / TypeORM delete(id)
        const keyArg =
          KEY_LOOKUPS.has(method) ||
          (WHERE_LOOKUPS.has(method) && args[0] && args[0].type !== 'Object')
            ? args[0]
            : undefined;
        if (keyArg && traceTaint(keyArg, { isSource: isClient }).tainted) {
          findings.push(
            finding(
              file,
              call,
              'idor',
              0.55,
              `${describe(route)}: ${model}.${method}(${shorten(textOf(file, keyArg), 40)}) looks up a record by a client-supplied id with no ownership check`,
            ),
          );
          continue;
        }

        // findOne({ where: { id } }) without an owner predicate
        if (WHERE_LOOKUPS.has(method)) {
          for (const where of whereObjects(call)) {
            const props = where.children.filter(
              (p) => p.type === 'Property' || p.rawType === 'ObjectProperty',
            );
            const hasOwner = props.some((p) => {
              const key = propertyKey(p) ?? '';
              const value = p.children.at(-1);
              return (
                OWNER_KEY.test(key) ||
                (value !== undefined && IDENTITY_TEXT.test(textOf(file, value)))
              );
            });
            const clientId = props.find((p) => {
              const key = propertyKey(p) ?? '';
              const value = p.children.at(-1);
              return (
                ID_KEY.test(key) &&
                !OWNER_KEY.test(key) &&
                value !== undefined &&
                traceTaint(value, { isSource: isClient }).tainted
              );
            });
            if (clientId && !hasOwner) {
              findings.push(
                finding(
                  file,
                  call,
                  'idor',
                  0.55,
                  `${describe(route)}: ${model}.${method}() selects by client-supplied "${propertyKey(clientId)}" (${shorten(textOf(file, clientId), 50)}) with no ownership predicate such as UserId: req.user.id`,
                ),
              );
              break;
            }
          }
        }

        // create({ BasketId: req.body.BasketId }): writing into a resource the user may not own
        if (WRITES.has(method)) {
          for (const arg of args) {
            for (const v of resolveValues(arg)) {
              if (v.type !== 'Object') continue;
              const fk = v.children.find((p) => {
                const key = propertyKey(p) ?? '';
                const value = p.children.at(-1);
                return (
                  p.type === 'Property' &&
                  OWNED_FK.test(key) &&
                  value !== undefined &&
                  traceTaint(value, { isSource: isClient }).tainted
                );
              });
              if (fk) {
                findings.push(
                  finding(
                    file,
                    call,
                    'idor',
                    0.55,
                    `${describe(route)}: ${model}.${method}() sets "${propertyKey(fk)}" from the request (${shorten(textOf(file, fk), 50)}) without verifying the user owns that ${propertyKey(fk)!.replace(/Id$/i, '')}`,
                  ),
                );
              }
            }
          }
        }
      }
    }
    return findings;
  },
});
