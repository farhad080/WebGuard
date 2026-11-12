// Shared by the API's extractor (EXTRACT_IGNORE_DIRS), the profiler, and the detection context.

/**
 * Directory names that are never extracted, profiled, or parsed: installed dependencies, build
 * output, caches, and VCS metadata. Matched against any directory segment of a path, so
 * `packages/a/node_modules/x.js` is ignored too. The API's EXTRACT_IGNORE_DIRS overrides it.
 *
 * Manifests and lockfiles at the project root (or any non-ignored directory) are unaffected, so
 * the dependency detector still sees them; the ones inside e.g. node_modules are not needed
 * (the root lockfile already pins every installed version).
 */
export const DEFAULT_IGNORED_DIRS: readonly string[] = [
  // installed dependencies
  'node_modules',
  'bower_components',
  'vendor',
  '.venv',
  'venv',
  '__pycache__',
  // build output & caches
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  'coverage',
  'target',
  '.gradle',
  '.cache',
  // version control
  '.git',
  '.hg',
  '.svn',
];

/**
 * The top-most ignored directory a `/`-separated relative path lies in (e.g.
 * `"a/node_modules"` for `"a/node_modules/b/c.js"`), or null. Only directory segments count:
 * a FILE named `build` is not ignored.
 */
export function ignoredDirOf(relPath: string, ignoredDirs: ReadonlySet<string>): string | null {
  const segments = relPath.split('/').filter(Boolean);
  const isDir = relPath.endsWith('/');
  const dirCount = isDir ? segments.length : segments.length - 1;
  for (let i = 0; i < dirCount; i++) {
    if (ignoredDirs.has(segments[i]!)) return segments.slice(0, i + 1).join('/');
  }
  return null;
}
