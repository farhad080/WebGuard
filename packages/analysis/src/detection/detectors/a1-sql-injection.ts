import { findAll, matchesName, textOf } from '../../ast/queries.js';
import {
  interpolatedParts,
  isStringBuilding,
  resolveValues,
  stringParts,
  traceTaint,
  type TaintTrace,
} from '../../ast/taint.js';
import type { AstNode } from '../../ast/types.js';
import { registerDetector } from '../registry.js';
import type { RawFinding } from '../types.js';
import { bestFlow, describeFlow, findingAt, parsedFiles, shorten } from './shared.js';

/**
 * A1 — SQL injection (dataflow).
 *
 * Objective: find raw SQL execution where the query string is built from request input.
 *
 * Logic:
 *  1. Sinks: `sequelize.query`, `knex.raw` / `*.raw`, Prisma `$queryRawUnsafe` /
 *     `$executeRawUnsafe`, `*.query` / `*.execute` (SQL-looking text only), and
 *     `db.run/all/get/each/exec` on database-like receivers.
 *  2. Take the first argument (following a variable back to its assignment), split it into
 *     its interpolated parts (`+` operands, `${}` expressions).
 *  3. Taint-trace each part to a request source (`req.body/query/params/headers/...`).
 *
 * Confidence: 0.9 (high) when a request source reaches the query directly; 0.6 (medium) when
 * it only gets there through an unknown function call; 0.5 (medium) when the string is
 * dynamic but no source can be proven in this file (e.g. built from a function parameter).
 *
 * False positives suppressed: parameterized queries (values in a bind/replacements array are
 * never part of the query string), queries built only from literals/constants/enums
 * (`TABLE`, `Status.ACTIVE`, `process.env.X`), numeric-coerced input (`Number(id)`),
 * escaped input (`*.escape(x)`), and ORM/query-builder calls (`findAll`, `where`, ...), which
 * bind values internally and are not sinks.
 *
 * Limitations: intra-procedural only; a query string built in another function or file is
 * seen as "dynamic, unproven" (medium) at best.
 */

const EXPLICIT_SINKS = [
  'sequelize.query',
  '*.sequelize.query',
  'knex.raw',
  '*.knex.raw',
  '*.$queryRawUnsafe',
  '*.$executeRawUnsafe',
];
/** Common method names; only treated as sinks when the query text looks like SQL. */
const GENERIC_SINKS = ['*.query', '*.execute', '*.raw'];
const DB_RECEIVER_METHODS = new Set(['run', 'all', 'get', 'each', 'exec']);
const DB_RECEIVER =
  /^(db|database|sqlite|sqlite3|conn|connection|pool|client|knex|sequelize|tx|trx)$/i;

const SQL_SANITIZERS = ['*.escape', 'escape', 'sqlstring.escape', 'SqlString.escape', '*.escapeId'];
const SQL_KEYWORDS =
  /\b(select|insert|update|delete|from|where|into|values|drop|union|order\s+by|group\s+by|join)\b/i;

const CATEGORY = 'A05:2025-Injection' as const;

function isSink(call: AstNode): 'explicit' | 'generic' | null {
  if (EXPLICIT_SINKS.some((p) => matchesName(call.name, p))) return 'explicit';
  const callee = call.callee;
  if (
    callee?.type === 'MemberAccess' &&
    callee.property &&
    DB_RECEIVER_METHODS.has(callee.property)
  ) {
    const receiver = callee.object?.name?.split('.').at(-1) ?? '';
    if (DB_RECEIVER.test(receiver)) return 'explicit';
  }
  if (GENERIC_SINKS.some((p) => matchesName(call.name, p))) return 'generic';
  return null;
}

function literalText(expr: AstNode): string {
  return stringParts(expr)
    .flatMap((p) =>
      p.type === 'StringLiteral'
        ? [p.value ?? '']
        : p.type === 'TemplateLiteral'
          ? p.children
              .filter((c) => c.rawType === 'TemplateElement')
              .map((c) => (c.raw as { value: { raw: string } }).value.raw)
          : [],
    )
    .join(' ');
}

interface Candidate {
  part: AstNode;
  trace: TaintTrace;
}

export const sqlInjection = registerDetector({
  id: 'A1-sql-injection',
  title: 'SQL injection',
  owaspCategory: CATEGORY,
  cwe: 'CWE-89',
  technique: 'dataflow',
  explanation:
    'User-controlled input is concatenated or interpolated directly into a SQL query string. ' +
    "The database can't tell data from code, so an attacker can close the string and add " +
    "their own SQL (e.g. `' OR 1=1--` to bypass a login, or `UNION SELECT` to dump other " +
    'tables), reading, modifying, or deleting data they should never reach.',
  fixSuggestion:
    'Use a parameterized query: keep the SQL constant with placeholders ($1 / ? / :name) and ' +
    'pass values separately (e.g. sequelize.query(sql, { replacements } or { bind })), or use ' +
    'the ORM query builder.',

  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of parsedFiles(ctx)) {
      for (const call of findAll(file, (n) => n.type === 'Call')) {
        const kind = isSink(call);
        const arg = call.arguments?.[0];
        if (!kind || !arg) continue;

        let best: { confidence: number; candidate: Candidate; proven: boolean } | undefined;
        for (const query of resolveValues(arg)) {
          if (
            query.type === 'StringLiteral' ||
            query.type === 'Function' ||
            query.type === 'Object'
          ) {
            continue;
          }
          const building = isStringBuilding(query);
          if (kind === 'generic' && building && !SQL_KEYWORDS.test(literalText(query))) continue;

          const parts = building ? interpolatedParts(query) : [query];
          for (const part of parts) {
            const trace = traceTaint(part, { sanitizers: SQL_SANITIZERS });
            let confidence = 0;
            if (trace.tainted) confidence = trace.direct ? 0.9 : 0.6;
            // Dynamic but unproven: only meaningful when the SQL itself is assembled here.
            else if (
              trace.dynamic &&
              building &&
              (kind === 'explicit' || SQL_KEYWORDS.test(literalText(query)))
            ) {
              confidence = 0.5;
            }
            if (confidence > (best?.confidence ?? 0)) {
              best = { confidence, candidate: { part, trace }, proven: trace.tainted };
            }
          }
        }
        if (!best) continue;

        const { part, trace } = best.candidate;
        const flow = bestFlow(trace);
        const sink = `${call.name ?? 'query'}()`;
        const evidence = flow
          ? `Request input ${describeFlow(file, part, flow)} is concatenated into the SQL passed to ${sink}`
          : `Dynamic value \`${shorten(textOf(file, part), 80)}\` is concatenated into the SQL passed to ${sink}; its origin could not be traced in this file`;

        findings.push(
          findingAt(ctx, file, call, {
            detectorId: 'A1-sql-injection',
            owaspCategory: CATEGORY,
            severity: best.proven ? 'critical' : 'high',
            confidence: best.confidence,
            evidence,
          }),
        );
      }
    }
    return findings;
  },
});
