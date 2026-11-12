import { open, readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import type {
  DetectedFramework,
  IgnoreReason,
  Language,
  LanguageStat,
  ManifestFile,
  ProjectProfile,
  SensitivePath,
  SensitivePathCategory,
  SourceFile,
} from '@webguard/core';
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
    const byReason: Record<IgnoreReason, number> = {
      'ignored-dir': 0,
      binary: 0,
      'too-large': 0,
      unrecognized: 0,
    };
    const files = await this.walk(path.resolve(rootDir), byReason);

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
        for (const fw of await this.frameworksFromManifest(file, base)) addFramework(fw);
      }

      const ext = path.posix.extname(base).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) {
        byReason.binary++;
        continue;
      }
      if (file.bytes > this.maxFileBytes) {
        byReason['too-large']++;
        continue;
      }
      const head = await readHead(file.abs);
      if (looksBinary(head)) {
        byReason.binary++;
        continue;
      }
      const language = detectLanguage(base, head.toString('utf8'));
      if (!language) {
        byReason.unrecognized++;
        continue;
      }

      sourceFiles.push({ path: file.rel, language, bytes: file.bytes });
      const stat = languageStats.get(language) ?? { language, files: 0, bytes: 0 };
      stat.files++;
      stat.bytes += file.bytes;
      languageStats.set(language, stat);
    }

    const ignoredTotal = Object.values(byReason).reduce((a, b) => a + b, 0);
    return {
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
  }

  /** Recursively lists regular files, skipping ignored dirs and never following symlinks. */
  private async walk(root: string, byReason: Record<IgnoreReason, number>): Promise<WalkedFile[]> {
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
  ): Promise<DetectedFramework[]> {
    if (file.bytes > this.maxFileBytes) return [];
    try {
      if (base === 'package.json') {
        const pkg = JSON.parse(await readFile(file.abs, 'utf8')) as Record<string, unknown>;
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
