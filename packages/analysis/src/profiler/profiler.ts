import { open, readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import type {
  DetectedFramework,
  IgnoreReason,
  Language,
  LanguageStat,
  LocCounts,
  ManifestFile,
  PackageManagerInfo,
  ProjectProfile,
  SensitivePath,
  SensitivePathCategory,
  SourceFile,
} from '@webguard/core';
import { countLines, countLoc } from '../stats/loc.js';
import { BINARY_EXTENSIONS, detectLanguage } from './languages.js';

export interface ProfilerOptions {
  /** Source files larger than this are skipped (minified bundles, generated code). */
  maxFileBytes?: number;
  /** Directory names that are never descended into. */
  ignoredDirs?: readonly string[];
}

import { DEFAULT_IGNORED_DIRS } from './ignored-dirs.js';

export { DEFAULT_IGNORED_DIRS };

const DEFAULT_MAX_FILE_BYTES = 1024 * 1024;
const SNIFF_BYTES = 8192;

const MANIFESTS: Record<string, ManifestFile['kind']> = {
  'package.json': 'manifest',
  'package-lock.json': 'lockfile',
  'npm-shrinkwrap.json': 'lockfile',
  'yarn.lock': 'lockfile',
  'pnpm-lock.yaml': 'lockfile',
  'requirements.txt': 'manifest',
  'pyproject.toml': 'manifest',
  Pipfile: 'manifest',
  'Pipfile.lock': 'lockfile',
  'poetry.lock': 'lockfile',
  'composer.json': 'manifest',
  'composer.lock': 'lockfile',
  Gemfile: 'manifest',
  'Gemfile.lock': 'lockfile',
  'go.mod': 'manifest',
  'go.sum': 'lockfile',
  'pom.xml': 'manifest',
  'build.gradle': 'manifest',
};

/** npm dependency → framework name. */
const NODE_FRAMEWORKS: Record<string, string> = {
  express: 'Express',
  koa: 'Koa',
  fastify: 'Fastify',
  '@nestjs/core': 'NestJS',
  '@hapi/hapi': 'hapi',
  next: 'Next.js',
  react: 'React',
  '@angular/core': 'Angular',
  vue: 'Vue',
  nuxt: 'Nuxt',
  svelte: 'Svelte',
  '@sveltejs/kit': 'SvelteKit',
  electron: 'Electron',
};

const RUNTIME_BY_MANIFEST: Record<string, string> = {
  'package.json': 'Node.js',
  'requirements.txt': 'Python',
  'pyproject.toml': 'Python',
  Pipfile: 'Python',
  'composer.json': 'PHP',
  Gemfile: 'Ruby',
  'go.mod': 'Go',
  'pom.xml': 'Java',
  'build.gradle': 'Java',
};

const PYTHON_FRAMEWORKS: Array<[RegExp, string]> = [
  [/^\s*django\b/im, 'Django'],
  [/^\s*flask\b/im, 'Flask'],
  [/^\s*fastapi\b/im, 'FastAPI'],
];

const SERVED_DIRS = new Set(['public', 'static', 'www', 'wwwroot', 'htdocs', 'public_html']);
const INFRA_DIRS = new Set([
  'infra',
  'infrastructure',
  'deploy',
  'deployment',
  'deployments',
  'k8s',
  'kubernetes',
  'helm',
  'charts',
  'ansible',
  'terraform',
  'ops',
  '.circleci',
  '.gitlab',
]);

function sensitiveCategories(relPath: string): SensitivePathCategory[] {
  const segments = relPath.split('/');
  const base = segments.at(-1)!;
  const dirs = segments.slice(0, -1);
  const lower = base.toLowerCase();
  const categories: SensitivePathCategory[] = [];

  if (/^\.env(\..+)?$/i.test(base) || lower.endsWith('.env')) categories.push('env');
  if (/^(Dockerfile|Containerfile)(\..+)?$/i.test(base) || lower.endsWith('.dockerfile')) {
    categories.push('dockerfile');
  }
  if (/^(docker-)?compose([.-].+)?\.ya?ml$/i.test(base)) categories.push('compose');
  if (/\.(tf|tfvars|tfstate)$/i.test(base) || lower.endsWith('.tfstate.backup')) {
    categories.push('terraform');
  }
  const inInfraDir =
    dirs.some((d) => INFRA_DIRS.has(d.toLowerCase())) || relPath.startsWith('.github/workflows/');
  if (inInfraDir && /\.ya?ml$/i.test(base)) categories.push('infra-config');
  if (
    /\.(pem|key|p12|pfx|jks|keystore)$/i.test(base) ||
    /^id_(rsa|dsa|ecdsa|ed25519)$/.test(base) ||
    ['.npmrc', '.pypirc', '.htpasswd', '.netrc', 'credentials.json'].includes(lower)
  ) {
    categories.push('key-material');
  }
  if (dirs.some((d) => SERVED_DIRS.has(d.toLowerCase()))) categories.push('static-served');
  return categories;
}

function looksBinary(head: Buffer): boolean {
  return head.includes(0);
}

async function readHead(file: string): Promise<Buffer> {
  const handle = await open(file, 'r');
  try {
    const { buffer, bytesRead } = await handle.read(Buffer.alloc(SNIFF_BYTES), 0, SNIFF_BYTES, 0);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

interface WalkedFile {
  rel: string;
  abs: string;
  bytes: number;
}

/** What profiling learned about one file (for the Project Overview statistics). */
export interface InventoryFile {
  path: string;
  bytes: number;
  language: Language | null;
  /** How the analysis treats it. */
  kind: 'source' | 'binary' | 'too-large' | 'unrecognized';
  /** Line count of a text file within the size limit; null when not read (binary / too large). */
  lines: number | null;
  /** Code/comment/blank split, for files in a recognized language. */
  loc: LocCounts | null;
}

/**
 * Per-file facts gathered in the same pass as the profile: every file is read at most once
 * (in full when it is a text file within `maxFileBytes`, which also yields its line counts).
 */
export interface ProjectInventory {
  files: InventoryFile[];
  /** Every extracted directory (project-relative, `/`-separated), excluding the root. */
  folders: string[];
  /** Likely entry points: package.json main / start script, then common conventions. */
  entryPoints: string[];
  packageManagers: PackageManagerInfo[];
}

const LOCKFILE_MANAGERS: Record<string, string> = {
  'package-lock.json': 'npm',
  'npm-shrinkwrap.json': 'npm',
  'yarn.lock': 'yarn',
  'pnpm-lock.yaml': 'pnpm',
  'Pipfile.lock': 'pipenv',
  'poetry.lock': 'poetry',
  'composer.lock': 'composer',
  'Gemfile.lock': 'bundler',
  'go.sum': 'go modules',
};
/** Manifest → the package manager it implies when no lockfile of that ecosystem exists. */
const MANIFEST_MANAGERS: Record<string, { name: string; lockfiles: string[] }> = {
  'package.json': {
    name: 'npm',
    lockfiles: ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'],
  },
  'requirements.txt': { name: 'pip', lockfiles: ['Pipfile.lock', 'poetry.lock'] },
  'pyproject.toml': { name: 'pip', lockfiles: ['Pipfile.lock', 'poetry.lock'] },
  Pipfile: { name: 'pipenv', lockfiles: ['Pipfile.lock'] },
  'composer.json': { name: 'composer', lockfiles: ['composer.lock'] },
  Gemfile: { name: 'bundler', lockfiles: ['Gemfile.lock'] },
  'go.mod': { name: 'go modules', lockfiles: ['go.sum'] },
  'pom.xml': { name: 'maven', lockfiles: [] },
  'build.gradle': { name: 'gradle', lockfiles: [] },
};

/** Conventional entry files, most specific first. */
const ENTRY_CONVENTIONS = [
  'server.js', 'server.ts', 'app.js', 'app.ts', 'index.js', 'index.ts', 'main.js', 'main.ts',
  'src/server.ts', 'src/server.js', 'src/index.ts', 'src/index.js', 'src/main.ts', 'src/main.js',
  'src/app.ts', 'src/app.js', 'bin/www', 'manage.py', 'app.py', 'main.py', 'wsgi.py', 'run.py',
  'index.php', 'public/index.php', 'main.go', 'cmd/main.go', 'Program.cs', 'config.ru',
  'index.html', 'public/index.html',
]; // prettier-ignore

const RUNNERS = new Set(['node', 'nodemon', 'ts-node', 'ts-node-dev', 'tsx', 'bun', 'deno']);

/** `node server.js`, `nodemon --watch src src/app.ts`, `ts-node ./x.ts` → the script's file. */
export function fileFromStartScript(script: string): string | null {
  for (const command of script.split(/&&|\|\||;/)) {
    const words = command.trim().split(/\s+/);
    const runner = words.findIndex((w) => RUNNERS.has(w));
    if (runner < 0) continue;
    // The first argument that looks like a file (has an extension or a path separator).
    const file = words
      .slice(runner + 1)
      .find((w) => !w.startsWith('-') && w !== 'run' && /[./]/.test(w) && !/^\d/.test(w));
    if (file) return file.replace(/^\.\//, '');
  }
  return null;
}

/**
 * Builds a {@link ProjectProfile} for an extracted project: what languages and frameworks it
 * uses, where its manifests and security-relevant files are, and which files to analyze.
 */
export class ProfilerService {
  private readonly maxFileBytes: number;
  private readonly ignoredDirs: Set<string>;

  constructor(options: ProfilerOptions = {}) {
    this.maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.ignoredDirs = new Set(options.ignoredDirs ?? DEFAULT_IGNORED_DIRS);
  }

  async profile(rootDir: string): Promise<ProjectProfile> {
    return (await this.run(rootDir, false)).profile;
  }

  /** The profile plus per-file facts (sizes, line counts, LOC split), in the same single pass. */
  async profileWithInventory(
    rootDir: string,
  ): Promise<{ profile: ProjectProfile; inventory: ProjectInventory }> {
    const { profile, inventory } = await this.run(rootDir, true);
    return { profile, inventory: inventory! };
  }

  private async run(
    rootDir: string,
    collect: boolean,
  ): Promise<{ profile: ProjectProfile; inventory?: ProjectInventory }> {
    const byReason: Record<IgnoreReason, number> = {
      'ignored-dir': 0,
      binary: 0,
      'too-large': 0,
      unrecognized: 0,
    };
    const folders: string[] = [];
    const files = await this.walk(path.resolve(rootDir), byReason, folders);
    const inventoryFiles: InventoryFile[] = [];
    let rootPackageJson: Record<string, unknown> | null = null;
    const record = (file: WalkedFile, entry: Omit<InventoryFile, 'path' | 'bytes'>) => {
      if (collect) inventoryFiles.push({ path: file.rel, bytes: file.bytes, ...entry });
    };

    const languageStats = new Map<Language, LanguageStat>();
    const sourceFiles: SourceFile[] = [];
    const manifests: ManifestFile[] = [];
    const sensitivePaths: SensitivePath[] = [];
    const frameworks = new Map<string, DetectedFramework>();
    let totalBytes = 0;

    const addFramework = (fw: DetectedFramework) => {
      if (!frameworks.has(fw.name)) frameworks.set(fw.name, fw);
    };

    for (const file of files) {
      totalBytes += file.bytes;
      const base = path.posix.basename(file.rel);

      for (const category of sensitiveCategories(file.rel)) {
        sensitivePaths.push({ path: file.rel, category });
      }

      const manifestKind = MANIFESTS[base];
      if (manifestKind) {
        manifests.push({ path: file.rel, type: base, kind: manifestKind });
        const runtime = RUNTIME_BY_MANIFEST[base];
        if (runtime) addFramework({ name: runtime, kind: 'runtime', evidence: file.rel });
        const onPackageJson = (pkg: Record<string, unknown>) => {
          if (file.rel === 'package.json') rootPackageJson = pkg;
        };
        for (const fw of await this.frameworksFromManifest(file, base, onPackageJson)) {
          addFramework(fw);
        }
      }

      const ext = path.posix.extname(base).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) {
        byReason.binary++;
        record(file, { language: null, kind: 'binary', lines: null, loc: null });
        continue;
      }
      if (file.bytes > this.maxFileBytes) {
        byReason['too-large']++;
        record(file, {
          language: detectLanguage(base),
          kind: 'too-large',
          lines: null,
          loc: null,
        });
        continue;
      }
      // With an inventory, the one read is a full read (line counts); otherwise just the head.
      const content = collect ? await readFile(file.abs) : null;
      const head = content ? content.subarray(0, SNIFF_BYTES) : await readHead(file.abs);
      if (looksBinary(head)) {
        byReason.binary++;
        record(file, { language: null, kind: 'binary', lines: null, loc: null });
        continue;
      }
      const language = detectLanguage(base, head.toString('utf8'));
      const text = content?.toString('utf8');
      if (!language) {
        byReason.unrecognized++;
        record(file, {
          language: null,
          kind: 'unrecognized',
          lines: text === undefined ? null : countLines(text),
          loc: null,
        });
        continue;
      }
      record(file, {
        language,
        kind: 'source',
        lines: text === undefined ? null : countLines(text),
        loc: text === undefined ? null : countLoc(text, language),
      });

      sourceFiles.push({ path: file.rel, language, bytes: file.bytes });
      const stat = languageStats.get(language) ?? { language, files: 0, bytes: 0 };
      stat.files++;
      stat.bytes += file.bytes;
      languageStats.set(language, stat);
    }

    const ignoredTotal = Object.values(byReason).reduce((a, b) => a + b, 0);
    const profile: ProjectProfile = {
      languages: [...languageStats.values()].sort(
        (a, b) => b.files - a.files || a.language.localeCompare(b.language),
      ),
      frameworks: [...frameworks.values()],
      manifests,
      sensitivePaths,
      sourceFiles,
      ignored: { total: ignoredTotal, byReason },
      totals: { files: files.length, bytes: totalBytes },
    };
    if (!collect) return { profile };
    return {
      profile,
      inventory: {
        files: inventoryFiles,
        folders,
        entryPoints: entryPointsOf(rootPackageJson, new Set(files.map((f) => f.rel))),
        packageManagers: packageManagersOf(manifests),
      },
    };
  }

  /** Recursively lists regular files, skipping ignored dirs and never following symlinks. */
  private async walk(
    root: string,
    byReason: Record<IgnoreReason, number>,
    folders: string[],
  ): Promise<WalkedFile[]> {
    const out: WalkedFile[] = [];
    const visit = async (dir: string): Promise<void> => {
      const entries = await readdir(dir, { withFileTypes: true });
      entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      for (const entry of entries) {
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (this.ignoredDirs.has(entry.name)) {
            byReason['ignored-dir'] += await countFiles(abs);
            continue;
          }
          folders.push(path.relative(root, abs).split(path.sep).join('/'));
          await visit(abs);
        } else if (entry.isFile()) {
          const rel = path.relative(root, abs).split(path.sep).join('/');
          out.push({ rel, abs, bytes: (await stat(abs)).size });
        }
      }
    };
    await visit(root);
    return out;
  }

  private async frameworksFromManifest(
    file: WalkedFile,
    base: string,
    onPackageJson?: (pkg: Record<string, unknown>) => void,
  ): Promise<DetectedFramework[]> {
    if (file.bytes > this.maxFileBytes) return [];
    try {
      if (base === 'package.json') {
        const pkg = JSON.parse(await readFile(file.abs, 'utf8')) as Record<string, unknown>;
        if (pkg && typeof pkg === 'object') onPackageJson?.(pkg);
        const deps = new Set<string>();
        for (const field of ['dependencies', 'devDependencies', 'peerDependencies']) {
          const value = pkg[field];
          if (value && typeof value === 'object') Object.keys(value).forEach((d) => deps.add(d));
        }
        return Object.entries(NODE_FRAMEWORKS)
          .filter(([dep]) => deps.has(dep))
          .map(([, name]) => ({ name, kind: 'framework' as const, evidence: file.rel }));
      }
      if (base === 'requirements.txt' || base === 'pyproject.toml' || base === 'Pipfile') {
        const text = await readFile(file.abs, 'utf8');
        return PYTHON_FRAMEWORKS.filter(([re]) => re.test(text)).map(([, name]) => ({
          name,
          kind: 'framework' as const,
          evidence: file.rel,
        }));
      }
      if (base === 'composer.json') {
        const text = await readFile(file.abs, 'utf8');
        return text.includes('laravel/framework')
          ? [{ name: 'Laravel', kind: 'framework', evidence: file.rel }]
          : [];
      }
    } catch {
      // A malformed manifest is not fatal; it simply reveals nothing.
    }
    return [];
  }
}

async function countFiles(dir: string): Promise<number> {
  let count = 0;
  try {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) count += await countFiles(path.join(dir, entry.name));
      else if (entry.isFile()) count++;
    }
  } catch {
    // unreadable: count nothing
  }
  return count;
}

function entryPointsOf(pkg: Record<string, unknown> | null, present: Set<string>): string[] {
  const out: string[] = [];
  const add = (p: string | null | undefined) => {
    const clean = p?.trim().replace(/^\.\//, '');
    if (clean && !out.includes(clean)) out.push(clean);
  };
  if (pkg) {
    if (typeof pkg.main === 'string') add(pkg.main);
    const scripts = pkg.scripts as Record<string, unknown> | undefined;
    for (const name of ['start', 'dev', 'serve']) {
      const script = scripts?.[name];
      if (typeof script === 'string') add(fileFromStartScript(script));
    }
  }
  for (const candidate of ENTRY_CONVENTIONS) if (present.has(candidate)) add(candidate);
  return out.slice(0, 5);
}

function packageManagersOf(manifests: readonly ManifestFile[]): PackageManagerInfo[] {
  const out: PackageManagerInfo[] = [];
  const seen = new Set<string>();
  // Root-level files first, then by path.
  const sorted = [...manifests].sort(
    (a, b) => a.path.split('/').length - b.path.split('/').length || a.path.localeCompare(b.path),
  );
  const lockTypes = new Set(sorted.filter((m) => m.kind === 'lockfile').map((m) => m.type));
  for (const m of sorted) {
    const name = LOCKFILE_MANAGERS[m.type];
    if (m.kind === 'lockfile' && name && !seen.has(name)) {
      seen.add(name);
      out.push({ name, lockfile: m.path });
    }
  }
  for (const m of sorted) {
    const implied = MANIFEST_MANAGERS[m.type];
    if (m.kind !== 'manifest' || !implied) continue;
    if (implied.lockfiles.some((l) => lockTypes.has(l)) || seen.has(implied.name)) continue;
    seen.add(implied.name);
    out.push({ name: implied.name, lockfile: null });
  }
  return out;
}
