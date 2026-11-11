import { describe, expect, it } from 'vitest';
import { createDefaultParserRegistry } from '../parse-project.js';
import { findCalls } from './queries.js';
import { interpolatedParts, isStringBuilding, resolveIdentifier, traceTaint } from './taint.js';
import type { AstNode } from './types.js';

const registry = createDefaultParserRegistry();

/** Parses `code` and returns the first argument of the first `sink(...)` call. */
function sinkArg(code: string): AstNode {
  const file = registry.parse({ path: 'x.js', language: 'javascript', sourceText: code });
  expect(file.parseError).toBeUndefined();
  const call = findCalls(file, ['sink'])[0];
  expect(call).toBeDefined();
  return call!.arguments![0]!;
}

const trace = (code: string, options?: Parameters<typeof traceTaint>[1]) =>
  traceTaint(sinkArg(code), options);

describe('traceTaint', () => {
  it('finds a direct source', () => {
    const t = trace('sink(req.body.name)');
    expect(t).toMatchObject({ tainted: true, direct: true, dynamic: true });
    expect(t.flows[0]!.source.name).toBe('req.body.name');
  });

  it('follows assignments, reassignments, and string methods', () => {
    const t = trace(`
      let q = req.query.q;
      q = q.trim().substring(0, 10);
      sink("x" + q);
    `);
    expect(t.tainted).toBe(true);
    expect(t.direct).toBe(true);
    expect(t.flows[0]!.via).toContain('q');
  });

  it('follows destructuring and for...of', () => {
    expect(trace('const { email } = req.body; sink(email)').tainted).toBe(true);
    expect(trace('for (const id of req.body.ids) { sink(id) }').tainted).toBe(true);
  });

  it('follows closures into outer function scopes', () => {
    expect(
      trace(`
        function handler(req) {
          const name = req.params.name;
          return () => sink(name);
        }
      `).tainted,
    ).toBe(true);
  });

  it('only counts the branches of a ternary, not the test', () => {
    expect(trace('sink(req.query.a ? "x" : "y")').tainted).toBe(false);
    expect(trace('sink(flag ? req.query.a : "y")').tainted).toBe(true);
  });

  it('treats numeric coercion and comparisons as sanitizing', () => {
    expect(trace('sink(Number(req.body.id))').tainted).toBe(false);
    expect(trace('sink(parseInt(req.query.page, 10))').tainted).toBe(false);
    expect(trace('sink(req.body.id === 1)').tainted).toBe(false);
    expect(trace('sink(req.body.name.length)').tainted).toBe(false);
  });

  it('marks flows through unknown calls as indirect', () => {
    const t = trace('sink(hash(req.body.password))');
    expect(t).toMatchObject({ tainted: true, direct: false });
  });

  it('honours custom sanitizers', () => {
    expect(trace('sink(db.escape(req.body.x))', { sanitizers: ['*.escape'] }).tainted).toBe(false);
  });

  it('applies scalar coercion only when asked (NoSQL vs SQL)', () => {
    const code = 'sink(String(req.body.id))';
    expect(trace(code).tainted).toBe(true); // String() doesn't stop SQL injection
    expect(trace(code, { coercionSanitizes: true }).tainted).toBe(false);
    expect(trace('sink(`${req.body.id}`)', { coercionSanitizes: true }).tainted).toBe(false);
  });

  it('distinguishes constants from dynamic-but-unproven values', () => {
    expect(trace('const T = "users"; sink("SELECT * FROM " + T)')).toMatchObject({
      tainted: false,
      dynamic: false,
    });
    expect(trace('sink("a" + Status.ACTIVE + process.env.TABLE)').dynamic).toBe(false);
    expect(trace('function f(name) { sink("a" + name) }')).toMatchObject({
      tainted: false,
      dynamic: true,
    });
  });

  it('ignores assignments that happen after the use', () => {
    expect(trace('let x = "safe"; sink(x); x = req.body.evil;').tainted).toBe(false);
  });

  it('follows this.field assignments across methods of a class', () => {
    const t = trace(`
      class C {
        value = '';
        init() { this.value = req.query.q; }
        render() { sink(this.value); }
      }
    `);
    expect(t.tainted).toBe(true);
    expect(t.flows[0]!.via).toContain('this.value');
  });

  it('follows a callback parameter back to the value it receives', () => {
    const t = trace('fetchOrder(req.query.id).then((order) => sink(order.html))');
    expect(t.tainted).toBe(true);
    expect(t.flows[0]).toMatchObject({ throughCallback: true, throughCall: true });
    // Only the first parameter receives the value.
    expect(trace('items.forEach((item, i) => sink(i))').tainted).toBe(false);
  });

  it('passes taint through identity calls like decodeURIComponent and bypassSecurityTrustHtml', () => {
    expect(trace('sink(decodeURIComponent(req.query.q))').direct).toBe(true);
    expect(trace('sink(this.s.bypassSecurityTrustHtml(req.query.q))').direct).toBe(true);
  });

  it('terminates on self-referencing assignments', () => {
    expect(trace('let s = ""; for (;;) { s = s + s; } sink(s)').tainted).toBe(false);
  });
});

describe('string-building helpers', () => {
  it('splits concatenations and templates into interpolated parts', () => {
    const arg = sinkArg('sink("a" + x + `b${y}c` + "d")');
    expect(isStringBuilding(arg)).toBe(true);
    expect(interpolatedParts(arg).map((p) => p.name)).toEqual(['x', 'y']);
    expect(isStringBuilding(sinkArg('sink("constant")'))).toBe(false);
  });

  it('resolves parameters and unresolved identifiers', () => {
    const param = sinkArg('function f(a) { sink(a) }');
    expect(resolveIdentifier(param).kind).toBe('parameter');
    expect(resolveIdentifier(sinkArg('sink(importedThing)')).kind).toBe('unresolved');
  });
});
