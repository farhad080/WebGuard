import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { ProjectProfile } from '@webguard/core';
import type { ParsedFile } from './ast/types.js';
import { BabelJsTsAdapter } from './parsers/babel-adapter.js';
import { ParserRegistry } from './parsers/registry.js';

/** Registry with every built-in adapter. Add new languages here (and only here). */
export function createDefaultParserRegistry(): ParserRegistry {
  return new ParserRegistry().register(new BabelJsTsAdapter());
}

/**
 * Parses every profiled source file that has an adapter, one at a time, so detectors can
 * stream through large projects without holding every AST in memory. Never throws for a bad
 * source file: read or parse failures surface as `parseError` on that file.
 */
export async function* parseSourceFiles(
  rootDir: string,
  profile: ProjectProfile,
  registry: ParserRegistry = createDefaultParserRegistry(),
): AsyncGenerator<ParsedFile> {
  const root = path.resolve(rootDir);
  for (const file of profile.sourceFiles) {
    if (!registry.supports(file.language)) continue;
    let sourceText: string;
    try {
      sourceText = await readFile(path.join(root, ...file.path.split('/')), 'utf8');
    } catch (err) {
      const parsed = registry.parse({ path: file.path, language: file.language, sourceText: '' });
      yield {
        ...parsed,
        ast: null,
        parseError: {
          message: `Could not read file: ${(err as Error).message}`,
          recovered: false,
        },
      };
      continue;
    }
    yield registry.parse({ path: file.path, language: file.language, sourceText });
  }
}
