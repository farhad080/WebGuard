import path from 'node:path';
import { findAll, matchesName, textOf, walk } from '../../ast/queries.js';
import { resolveValues } from '../../ast/taint.js';
import type { AstNode, ParsedFile } from '../../ast/types.js';
import { registerDetector } from '../registry.js';
import type { Severity } from '@webguard/core';
import type { DetectionContext, RawFinding } from '../types.js';
import { findingAt, parsedFiles, shorten } from './shared.js';

/**
 * A7 — Sensitive / backup file exposure (config).
 *
 * 1. Served roots: `express.static(dir)`, `serveStatic(dir)`, `serveIndex(dir)`, file-server
 *    routes (`res.sendFile(path.resolve('ftp/', file))`), plus the profiler's static dirs
 *    (public/, static/, www/ …). Files inside a served root that look like backups, dumps,
 *    IaC, env files, keys, credential stores, or confidential documents are reported, high.
 *    Juice Shop #12 (confidential acquisitions.md), #16 (coupons_2013.md.bak), #18
 *    (package.json.bak), #38 (/ftp file server).
 * 2. Directory listing (`serveIndex`) on a served root, medium.
 * 3. Suffix-only type filters guarding a file-serving route (`file.endsWith('.md')`, a
 *    `/\.(md|pdf)$/` test) are bypassable with a poison null byte (`x.bak%2500.md`) or a
 *    double extension, high. Juice Shop #38.
 * 4. Best effort: a JSONP endpoint (`res.jsonp`) returns data with a client-chosen callback,
 *    so any site can read the response cross-domain (Juice Shop #19, user email via JSONP).
 *    Low confidence. Pure information-disclosure items such as #17 (a blueprint left in a
 *    public folder, metadata in files) need manual or dynamic review.
 */

const CATEGORY = 'A02:2025-Security Misconfiguration' as const;

interface SensitiveKind {
  label: string;
  re: RegExp;
  severity: Severity;
  confidence: number;
}

const SENSITIVE_FILES: SensitiveKind[] = [
  {
    label: 'backup file',
    re: /\.(bak|old|orig|backup|bkp|swp|save|tmp)$|~$|\.(bak|old)\.[^/]+$/i,
    severity: 'high',
    confidence: 0.85,
  },
  {
    label: 'database dump',
    re: /\.(sql|sqlite3?|db|dump|mdb)$|(^|\/)dump[^/]*$/i,
    severity: 'high',
    confidence: 0.8,
  },
  {
    label: 'infrastructure-as-code',
    re: /\.(tf|tfvars|tfstate)$|(^|\/)(docker-compose[^/]*|Dockerfile[^/]*)$/i,
    severity: 'high',
    confidence: 0.8,
  },
  {
    label: 'environment/config file',
    re: /(^|\/)\.env[^/]*$|(^|\/)\.(npmrc|htpasswd|htaccess|git-credentials)$|(^|\/)(config|settings|secrets?)\.(json|ya?ml|ini)$/i,
    severity: 'high',
    confidence: 0.85,
  },
  {
    label: 'key or certificate',
    re: /\.(pem|key|p12|pfx|jks|keystore|crt)$|(^|\/)id_(rsa|dsa|ecdsa|ed25519)[^/]*$/i,
    severity: 'high',
    confidence: 0.85,
  },
  {
    label: 'credential store',
    re: /\.(kdbx|kdb|keychain|psafe3)$/i,
    severity: 'high',
    confidence: 0.85,
  },
  {
    label: 'source control metadata',
    re: /(^|\/)\.(git|svn|hg)\//,
    severity: 'high',
    confidence: 0.85,
  },
  {
    label: 'compiled source / log',
    re: /\.(pyc|class|log)$/i,
    severity: 'medium',
    confidence: 0.6,
  },
  {
    label: 'possibly confidential document',
    re: /(confidential|acquisition|internal|secret|private|salar(y|ies)|payroll|password|credential|invoice|contract)[^/]*\.(md|pdf|docx?|xlsx?|txt|csv)$/i,
    severity: 'high',
    confidence: 0.55,
  },
];

const STATIC_CALLS = ['express.static', 'serveStatic', 'serve-static', 'koaStatic', 'serve'];
const SEND_FILE_METHODS = new Set(['sendFile', 'download', 'sendfile']);
const SUFFIX_FILTER =
  /\.endsWith\(\s*['"`]\.\w+['"`]|endsWith\(\s*\w+\s*,\s*['"`]\.\w+['"`]\s*\)|\/\\\.\(?[\w|]+\)?\$\/(?:[gimsuy]*)\.test\(|\.match\(\s*\/\\\.\(?[\w|]+\)?\$\/|path\.extname\([^)]*\)\s*[!=]==?\s*['"`]\.\w+/;

const EXPLAIN = {
  exposed:
    'Files that should never be public (backups, dumps, keys, env/config files, credential ' +
    'stores, confidential documents) sit inside a directory the server serves to anyone. ' +
    'Attackers routinely probe for names like package.json.bak or *.sql, which reveal source, ' +
    'dependencies, credentials, or business data.',
  listing:
    'Directory listing is enabled on a served directory, so anyone can browse every file in it ' +
    'and discover backups and documents that were never linked.',
  filter:
    'The file-serving route only checks the file name suffix (e.g. ends with ".md"). Suffix ' +
    'checks are bypassable: a poison null byte (package.json.bak%2500.md) or a double ' +
    'extension makes a forbidden file pass the check, which exposes any file in the served directory.',
  jsonp:
    'Best-effort, low confidence: this endpoint answers JSONP with a client-chosen callback, so ' +
    "any website can read the response cross-domain (e.g. the logged-in user's email). Confirm " +
    'what data it returns. Pure information-disclosure issues (hidden files, metadata in ' +
    'images or documents) need manual or dynamic review and are not detected from source.',
};
const FIX = {
  exposed:
    'Serve only an explicit public directory, move backups/keys/dumps out of it (and out of the ' +
    'deployment), and validate requested paths against an allowlist.',
  listing:
    'Disable directory listing (remove serveIndex) and serve only an explicit public directory.',
  filter:
    'Decode the requested name first, reject it unless it exactly matches an allowlist of ' +
    'known files (or a strict /^[\\w-]+\\.(md|pdf)$/ on the decoded name), and resolve it with ' +
    'path checks so it stays inside the served directory.',
  jsonp:
    'Remove JSONP (use CORS with an explicit origin allowlist) and never return personal data to ' +
    'cross-origin callers.',
};

function stringOf(node: AstNode | undefined): string | undefined {
  if (!node) return undefined;
  for (const v of resolveValues(node)) {
    if (v.type === 'StringLiteral') return v.value;
    if (v.type === 'TemplateLiteral' && v.value !== undefined) return v.value;
    // path.join(__dirname, 'public') / path.resolve('ftp/')
    if (v.type === 'Call' && /(^|\.)(join|resolve)$/.test(v.name ?? '')) {
      const literals = (v.arguments ?? [])
        .map(stringOf)
        .filter((s): s is string => s !== undefined);
      if (literals.length > 0) return literals.join('/');
    }
  }
  return undefined;
}

/** Project-relative root of a served dir, resolved like Express does (cwd or __dirname). */
function servedRoot(dir: string, file: ParsedFile, all: readonly string[]): string | undefined {
  const clean = dir.replace(/^\.?\/+/, '').replace(/\/+$/, '');
  const candidates = [
    clean,
    path.posix.join(path.posix.dirname(file.path), clean).replace(/^\.\//, ''),
  ];
  return candidates.find((c) => c === '' || all.some((f) => f.startsWith(`${c}/`)));
}

interface Root {
  dir: string;
  file?: ParsedFile;
  at?: AstNode;
  how: string;
}

function collectRoots(ctx: DetectionContext): { roots: Root[]; listings: Root[] } {
  const roots: Root[] = [];
  const listings: Root[] = [];
  for (const file of parsedFiles(ctx)) {
    for (const call of findAll(file, (n) => n.type === 'Call')) {
      const name = call.name ?? '';
      const isStatic = STATIC_CALLS.some((p) => matchesName(name, p));
      const isIndex =
        name === 'serveIndex' || matchesName(name, '*.serveIndex') || name === 'express.directory';
      const isSendFile =
        call.callee?.type === 'MemberAccess' && SEND_FILE_METHODS.has(call.callee.property ?? '');
      if (!isStatic && !isIndex && !isSendFile) continue;
      const dir = stringOf(call.arguments?.[0]);
      if (dir === undefined) continue;
      const root = servedRoot(dir, file, ctx.allFiles);
      if (root === undefined) continue;
      const entry: Root = { dir: root, file, at: call, how: `${name}('${dir}')` };
      if (isIndex) listings.push(entry);
      roots.push(entry);
    }
  }
  // The profiler's served dirs (public/, static/, …) count even without explicit config.
  for (const p of ctx.configPaths) {
    if (p.category !== 'static-served') continue;
    const segments = p.path.split('/');
    const idx = segments.findIndex((s) =>
      /^(public|static|www|wwwroot|htdocs|public_html)$/i.test(s),
    );
    if (idx < 0) continue;
    const dir = segments.slice(0, idx + 1).join('/');
    if (!roots.some((r) => r.dir === dir)) roots.push({ dir, how: `served directory ${dir}/` });
  }
  // Prefer explicit static/index mounts over file-serving routes when attributing a root.
  const rank = (r: Root) => (/\.(sendFile|download|sendfile)\(/.test(r.how) ? 1 : 0);
  roots.sort((a, b) => rank(a) - rank(b));
  return { roots, listings };
}

export const sensitiveFileExposure = registerDetector({
  id: 'A7-sensitive-file-exposure',
  title: 'Sensitive or backup file exposure',
  owaspCategory: CATEGORY,
  cwe: 'CWE-538',
  technique: 'config',
  explanation: EXPLAIN.exposed,
  fixSuggestion: FIX.exposed,

  run(ctx) {
    const findings: RawFinding[] = [];
    const { roots, listings } = collectRoots(ctx);

    // ---- 1. Sensitive files inside served roots ----
    const reported = new Set<string>();
    for (const root of roots) {
      const inside = ctx.allFiles.filter((f) =>
        root.dir === '' ? true : f.startsWith(`${root.dir}/`),
      );
      for (const filePath of inside) {
        if (reported.has(filePath)) continue;
        const kind = SENSITIVE_FILES.find((k) => k.re.test(filePath));
        if (!kind) continue;
        reported.add(filePath);
        const where =
          root.file && root.at
            ? ` (served by ${root.how} at ${root.file.path}:${root.at.loc.startLine})`
            : ` (${root.how})`;
        // Located at the exposed file itself so the report points at what to remove.
        const text = ctx.readText(filePath);
        const printable = text !== null && !text.includes('\u0000');
        findings.push({
          detectorId: 'A7-sensitive-file-exposure',
          owaspCategory: CATEGORY,
          severity: kind.severity,
          confidence: kind.confidence,
          filePath,
          lineStart: 1,
          lineEnd: 1,
          snippet: printable ? ctx.snippet(filePath, 1) : '[binary file]',
          evidence: `${kind.label} "${path.posix.basename(filePath)}" is publicly served${where}`,
          cwe: 'CWE-538',
        });
      }
    }

    // ---- 2. Directory listing ----
    for (const l of listings) {
      if (!l.file || !l.at) continue;
      findings.push(
        findingAt(ctx, l.file, l.at, {
          detectorId: 'A7-sensitive-file-exposure',
          owaspCategory: CATEGORY,
          severity: 'medium',
          confidence: 0.9,
          evidence: `directory listing enabled for ${l.dir || '/'} via ${l.how}`,
          explanation: EXPLAIN.listing,
          fixSuggestion: FIX.listing,
          cwe: 'CWE-548',
        }),
      );
    }

    // ---- 3. Suffix-only filters on file-serving routes ----
    for (const file of parsedFiles(ctx)) {
      if (!SUFFIX_FILTER.test(file.sourceText)) continue;
      for (const call of findAll(
        file,
        (n) =>
          n.type === 'Call' &&
          n.callee?.type === 'MemberAccess' &&
          SEND_FILE_METHODS.has(n.callee.property ?? ''),
      )) {
        const arg = textOf(file, call.arguments?.[0] ?? call);
        if (!/\b(params|query|body|file(name)?|req)\b/.test(arg)) continue;
        const nullByteNote = /cutOffPoisonNullByte|\\0|%00|\\u0000/.test(file.sourceText)
          ? '; the null byte is stripped only after the suffix check'
          : '';
        findings.push(
          findingAt(ctx, file, call, {
            detectorId: 'A7-sensitive-file-exposure',
            owaspCategory: CATEGORY,
            severity: 'high',
            confidence: 0.6,
            evidence: `${call.name}(${shorten(arg, 50)}) is guarded only by a file-name suffix check${nullByteNote}: bypassable with "%2500.md" or a double extension`,
            explanation: EXPLAIN.filter,
            fixSuggestion: FIX.filter,
            cwe: 'CWE-22',
          }),
        );
      }
    }

    // ---- 4. JSONP endpoints (best effort) ----
    for (const file of parsedFiles(ctx)) {
      for (const call of walk(file)) {
        if (call.type !== 'Call' || call.callee?.property !== 'jsonp') continue;
        findings.push(
          findingAt(ctx, file, call, {
            detectorId: 'A7-sensitive-file-exposure',
            owaspCategory: CATEGORY,
            severity: 'medium',
            confidence: 0.35,
            evidence: `best effort: ${call.name}() serves JSONP with a client-chosen callback; check whether it returns user data`,
            explanation: EXPLAIN.jsonp,
            fixSuggestion: FIX.jsonp,
            cwe: 'CWE-359',
          }),
        );
      }
    }
    return findings;
  },
});
