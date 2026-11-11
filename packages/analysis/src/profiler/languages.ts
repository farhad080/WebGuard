import type { Language } from '@webguard/core';

const BY_EXTENSION: Record<string, Language> = {
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.tsx': 'typescript',
  '.py': 'python',
  '.php': 'php',
  '.phtml': 'php',
  '.rb': 'ruby',
  '.java': 'java',
  '.go': 'go',
  '.cs': 'csharp',
  '.html': 'html',
  '.htm': 'html',
  '.css': 'css',
  '.scss': 'css',
  '.sass': 'css',
  '.less': 'css',
  '.vue': 'vue',
  '.svelte': 'svelte',
  '.json': 'json',
  '.yml': 'yaml',
  '.yaml': 'yaml',
  '.toml': 'toml',
  '.xml': 'xml',
  '.sql': 'sql',
  '.sh': 'shell',
  '.bash': 'shell',
  '.zsh': 'shell',
  '.tf': 'terraform',
  '.tfvars': 'terraform',
  '.dockerfile': 'dockerfile',
  '.md': 'markdown',
};

/** Extensions never worth reading as text. */
export const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.tiff', '.avif',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.zip', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.tar', '.jar', '.war',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.class', '.o', '.a', '.wasm', '.node',
  '.pdf', '.mp3', '.mp4', '.mov', '.avi', '.webm', '.wav', '.ogg',
  '.sqlite', '.db', '.p12', '.pfx', '.der',
]); // prettier-ignore

const SHEBANGS: Array<[RegExp, Language]> = [
  [/\bnode\b|\bdeno\b|\bbun\b/, 'javascript'],
  [/\bts-node\b|\btsx\b/, 'typescript'],
  [/\bpython[0-9.]*\b/, 'python'],
  [/\bphp\b/, 'php'],
  [/\bruby\b/, 'ruby'],
  [/\b(ba|z|da)?sh\b/, 'shell'],
];

/**
 * Detects a file's language from its name, falling back to content heuristics
 * (shebang lines, `<?php` openers) for files without a known extension.
 */
export function detectLanguage(basename: string, head?: string): Language | null {
  if (/^Dockerfile(\..+)?$/i.test(basename) || /^Containerfile$/i.test(basename)) {
    return 'dockerfile';
  }
  const dot = basename.lastIndexOf('.');
  const ext = dot > 0 ? basename.slice(dot).toLowerCase() : '';
  const byExt = BY_EXTENSION[ext];
  if (byExt) return byExt;

  if (head !== undefined && (ext === '' || dot === 0)) {
    const firstLine = head.split('\n', 1)[0] ?? '';
    if (firstLine.startsWith('#!')) {
      for (const [pattern, language] of SHEBANGS) if (pattern.test(firstLine)) return language;
    }
    if (head.trimStart().startsWith('<?php')) return 'php';
  }
  return null;
}

/** Languages that a parser adapter may turn into an AST (vs. data/config formats). */
export const CODE_LANGUAGES: ReadonlySet<Language> = new Set<Language>([
  'javascript', 'typescript', 'python', 'php', 'ruby', 'java', 'go', 'csharp',
  'html', 'vue', 'svelte', 'shell', 'sql',
]); // prettier-ignore
