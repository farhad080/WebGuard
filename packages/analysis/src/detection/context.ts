import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import type { ProjectProfile } from '@webguard/core';
import type { ParsedFile } from '../ast/types.js';
import { getSnippet } from './snippet.js';
import type { DetectionContext } from './types.js';

export interface DetectionContextInput {
  /** Root of the extracted project on disk. */
  rootDir: string;
  profile: ProjectProfile;
  files: readonly ParsedFile[];
  /** `readText` refuses files larger than this (default 5 MB). */
  maxReadBytes?: number;
}

const DEFAULT_MAX_READ_BYTES = 5 * 1024 * 1024;

export function createDetectionContext(input: DetectionContextInput): DetectionContext {
  const root = path.resolve(input.rootDir);
  const maxReadBytes = input.maxReadBytes ?? DEFAULT_MAX_READ_BYTES;
  const parsedByPath = new Map(input.files.map((f) => [f.path, f]));
  const textCache = new Map<string, string | null>();

  const readText = (relPath: string): string | null => {
    const parsed = parsedByPath.get(relPath);
    if (parsed) return parsed.sourceText;
    if (textCache.has(relPath)) return textCache.get(relPath)!;

    let text: string | null = null;
    const segments = relPath.split('/');
    // Project-relative paths only: never let a detector read outside the extracted tree.
    if (
      relPath !== '' &&
      !relPath.includes('\\') &&
      !path.isAbsolute(relPath) &&
      !segments.some((s) => s === '..' || s === '')
    ) {
      const abs = path.resolve(root, ...segments);
      const rel = path.relative(root, abs);
      if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
        try {
          const stat = statSync(abs);
          if (stat.isFile() && stat.size <= maxReadBytes) text = readFileSync(abs, 'utf8');
        } catch {
          text = null;
        }
      }
    }
    textCache.set(relPath, text);
    return text;
  };

  return {
    profile: input.profile,
    files: input.files,
    sourceFiles: input.profile.sourceFiles,
    manifests: input.profile.manifests,
    configPaths: input.profile.sensitivePaths,
    getParsedFile: (p) => parsedByPath.get(p),
    readText,
    snippet: (p, lineStart, lineEnd = lineStart) => {
      const parsed = parsedByPath.get(p);
      if (parsed) return getSnippet(parsed.lineIndex, lineStart, lineEnd);
      const text = readText(p);
      return text === null ? '' : getSnippet(text, lineStart, lineEnd);
    },
  };
}
