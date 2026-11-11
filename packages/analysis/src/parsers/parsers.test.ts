import { readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import type { Language } from '@webguard/core';
import { describe, expect, it } from 'vitest';
import { MINI_EXPRESS, materializeMiniExpress } from '../../test/fixture-project.js';
import {
  containsSource,
  findAssignments,
  findCalls,
  findMemberWrites,
  findStringLiterals,
  findTagged,
  textOf,
} from '../ast/queries.js';
import type { ParsedFile } from '../ast/types.js';
import { createDefaultParserRegistry, parseSourceFiles } from '../parse-project.js';
import { ProfilerService } from '../profiler/profiler.js';
import { ParserRegistry, type ParserAdapter } from './registry.js';

const registry = createDefaultParserRegistry();

async function parseFixture(rel: string, language: Language = 'javascript'): Promise<ParsedFile> {
  const sourceText = await readFile(path.join(MINI_EXPRESS, ...rel.split('/')), 'utf8');
  return registry.parse({ path: rel, language, sourceText });
}

describe('Babel JS/TS adapter + AST helpers', () => {
  it('finds a db.query(...) call with its exact location', async () => {
    const file = await parseFixture('src/routes/users.js');
    expect(file.parseError).toBeUndefined();

    const calls = findCalls(file, ['db.query']);
    expect(calls.map((c) => c.loc.startLine)).toEqual([8, 13]);
    expect(textOf(file, calls[0]!)).toBe(
      `db.query("SELECT * FROM users WHERE name = '" + name + "'")`,
    );
    expect(calls[0]!.arguments?.[0]?.type).toBe('Binary');
    // Wildcard receivers
    expect(findCalls(file, ['*.query'])).toHaveLength(2);
  });

  it('tags req.body / req.params reads as taint sources', async () => {
    const file = await parseFixture('src/routes/users.js');
    const sources = findTagged(file, 'source:http-input');
    expect(sources.map((n) => [n.name, n.loc.startLine])).toEqual(
      expect.arrayContaining([
        ['req.body.name', 7],
        ['req.body', 7],
        ['req.params.id', 13],
      ]),
    );
    // `const name = req.body.name`: the assigned value contains a source.
    const nameDecl = findAssignments(file, { targets: ['name'] })[0]!;
    expect(containsSource(nameDecl.right!)).toBe(true);
    // res.json(...) is not a source.
    expect(findTagged(file, 'source:*').some((n) => n.name?.startsWith('res'))).toBe(false);
  });

  it('finds an el.innerHTML = x write and tags it as a DOM sink', async () => {
    const file = await parseFixture('src/client/widget.js');
    const writes = findMemberWrites(file, ['innerHTML']);
    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({ name: 'el.innerHTML', loc: { startLine: 2 } });
    expect(writes[0]!.tags).toContain('sink:dom-html');
    // el.title is a member write too, but not to innerHTML.
    expect(findMemberWrites(file, ['title'])).toHaveLength(1);
  });

  it('parses TypeScript (with type assertions and decorators)', () => {
    const file = registry.parse({
      path: 'src/ctrl.ts',
      language: 'typescript',
      sourceText: [
        '@Controller("users")',
        'export class UsersController {',
        '  find(req: Request) {',
        '    const q = (req as any).query.search as string;',
        '    return this.repo.query(`SELECT 1`);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(file.parseError).toBeUndefined();
    expect(findTagged(file, 'source:http-input').map((n) => n.name)).toContain('req.query.search');
    expect(findCalls(file, ['this.repo.query'])).toHaveLength(1);
    expect(findStringLiterals(file).map((n) => n.value)).toEqual(['users', 'SELECT 1']);
  });

  it('exposes parent links and the raw Babel node without breaking JSON', async () => {
    const file = await parseFixture('src/client/widget.js');
    const write = findMemberWrites(file, ['innerHTML'])[0]!;
    expect(write.parent?.rawType).toBe('ExpressionStatement');
    expect((write.raw as { type: string }).type).toBe('AssignmentExpression');
    expect(() => JSON.stringify(file.ast)).not.toThrow();
  });
});

describe('parse errors', () => {
  it('records a non-fatal parseError for a broken file', async () => {
    const file = await parseFixture('src/legacy/broken.js');
    expect(file.ast).toBeNull();
    expect(file.parseError).toMatchObject({ recovered: false, line: expect.any(Number) });
  });

  it('keeps an AST when Babel can recover', () => {
    const file = registry.parse({
      path: 'dup.js',
      language: 'javascript',
      sourceText: 'let a = 1;\nlet a = 2;\neval(a);',
    });
    expect(file.ast).not.toBeNull();
    expect(file.parseError).toMatchObject({ recovered: true, line: 2 });
    expect(findTagged(file, 'sink:code-exec')).toHaveLength(1);
  });

  it('turns an adapter crash into a parseError instead of throwing', () => {
    const crashing: ParserAdapter = {
      id: 'crash',
      languages: ['python'],
      parse: () => {
        throw new Error('boom');
      },
    };
    const reg = new ParserRegistry().register(crashing);
    expect(reg.parse({ path: 'a.py', language: 'python', sourceText: 'x' })).toMatchObject({
      ast: null,
      parseError: { message: 'boom', recovered: false },
    });
  });

  it('parses a whole project and continues past the broken file', async () => {
    const root = await materializeMiniExpress();
    try {
      const profile = await new ProfilerService().profile(root);
      const results: ParsedFile[] = [];
      for await (const file of parseSourceFiles(root, profile)) results.push(file);

      // vendor.min.js (a 3000-deep expression) is under the 1 MiB cap, so it's parsed too.
      expect(results.map((f) => f.path)).toEqual([
        'scripts/start',
        'src/client/widget.js',
        'src/legacy/broken.js',
        'src/routes/users.js',
        'src/server.ts',
        'src/vendor.min.js',
      ]);
      const failed = results.filter((f) => f.parseError);
      expect(failed.map((f) => f.path)).toEqual(['src/legacy/broken.js']);
      expect(results.filter((f) => f.ast).length).toBe(5);
      expect(results.find((f) => f.path === 'src/vendor.min.js')?.ast).not.toBeNull();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('ParserRegistry', () => {
  it('lets a new language be added by registering an adapter', () => {
    const reg = createDefaultParserRegistry();
    expect(reg.supports('python')).toBe(false);
    reg.register({
      id: 'fake-python',
      languages: ['python'],
      parse: () => ({
        ast: {
          type: 'Program',
          rawType: 'Module',
          loc: { startLine: 1, startCol: 0, endLine: 1, endCol: 1 },
          children: [],
          tags: [],
        },
      }),
    });
    expect(reg.supports('python')).toBe(true);
    expect(reg.parse({ path: 'a.py', language: 'python', sourceText: 'x' }).ast?.type).toBe(
      'Program',
    );
  });

  it('refuses two adapters for the same language', () => {
    const reg = createDefaultParserRegistry();
    expect(() =>
      reg.register({ id: 'dup', languages: ['javascript'], parse: () => ({ ast: null }) }),
    ).toThrow(/already handled/);
  });

  it('reports unsupported languages as a parseError', () => {
    expect(
      registry.parse({ path: 'a.go', language: 'go', sourceText: 'package main' }),
    ).toMatchObject({
      ast: null,
      parseError: { recovered: false },
    });
  });
});
