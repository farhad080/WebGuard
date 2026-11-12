import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import type { ProjectProfile } from '@webguard/core';
import type { ParsedFile } from '../ast/types.js';
import { DEFAULT_IGNORED_DIRS } from '../profiler/ignored-dirs.js';
import { getSnippet } from './snippet.js';
import type { DetectionContext } from './types.js';

export interface DetectionContextInput {
  /** Root of the extracted project on disk. */
  rootDir: string;
  profile: ProjectProfile;
  files: readonly ParsedFile[];
  /** `readText` refuses files larger than this (default 5 MB). */
  maxReadBytes?: number;
  /** Directory names never listed in `allFiles` (same list as the profiler/extractor). */
  ignoredDirs?: readonly string[];
}

const DEFAULT_MAX_READ_BYTES = 5 * 1024 * 1024;
const MAX_LISTED_FILES = 50_000;

/** Every regular file in the project (incl. binaries and unrecognized types), `/`-separated. */
function listAllFiles(root: string, skipDirs: ReadonlySet<string>): string[] {
  const out: string[] = [];
  const visit = (dir: string) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (out.length >= MAX_LISTED_FILES) return;
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) visit(abs);
      } else if (entry.isFile()) {
        out.push(path.relative(root, abs).split(path.sep).join('/'));
      }
    }
  };
  visit(root);
  return out.sort();
}

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
    allFiles: listAllFiles(root, new Set(input.ignoredDirs ?? DEFAULT_IGNORED_DIRS)),
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
