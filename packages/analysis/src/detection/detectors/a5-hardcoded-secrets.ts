import path from 'node:path';
import { matchesName, walk } from '../../ast/queries.js';
import { resolveValues } from '../../ast/taint.js';
import type { AstNode } from '../../ast/types.js';
import { registerDetector } from '../registry.js';
import type { DetectionContext, Detector, RawFinding } from '../types.js';
import { isClientSide, isTestPath, redact } from './shared.js';

/**
 * A5 — Hardcoded secrets (pattern).
 *
 * Objective: find credentials committed to source, and flag the worst case (secrets shipped
 * inside a browser bundle) as critical.
 *
 * Logic:
 *  1. Known key formats over raw text (any file type): AWS access key IDs / secret keys,
 *     Google API keys, Slack tokens & webhooks, GitHub / npm / Stripe / SendGrid tokens,
 *     JWTs, PEM private keys, and passwords embedded in connection URLs.
 *  2. Credential assignments with a non-empty literal: `password = '…'`, `{ apiKey: '…' }`,
 *     class fields, `KEY=value` lines in .env / YAML / JSON, and literal keys passed to
 *     `createHmac`, `createCipheriv`, `jwt.sign/verify`, `cookieParser`.
 *  3. High-entropy string literals (Shannon entropy ≥ a tunable threshold, mixed charset).
 *
 * Severity: critical when the file is client-side (served/static dir, front-end source,
 * component files, Angular/React/Vue imports), because the secret goes to every browser. Juice
 * Shop #14 (testing credentials in the Angular login component) is this case. Otherwise high.
 * Confidence: 0.95 private keys, ~0.9 vendor key formats, 0.85 literal crypto/JWT keys,
 * 0.75 credential assignments, 0.45 (low) entropy-only.
 *
 * False positives suppressed: placeholder/example values (changeme, xxx, your-key-here,
 * example, `${VAR}`, ...), test/fixture/mock/spec paths, lockfiles, public keys / publishable
 * keys / OAuth client IDs, i18n keys, prose, URLs and file paths, and UUID / hash-shaped
 * strings outside a credential context.
 *
 * Redaction: evidence and snippet never contain the full value, only a short prefix.
 */

export interface SecretsDetectorOptions {
  /** Minimum Shannon entropy (bits/char) for mixed-charset strings (default 4.5). */
  entropyThreshold?: number;
  /** Minimum entropy for hex strings (default 3.5). */
  hexEntropyThreshold?: number;
  /** Minimum length for entropy-only candidates (default 20). */
  minEntropyLength?: number;
}

const CATEGORY = 'A04:2025-Cryptographic Failures' as const;

interface KnownFormat {
  label: string;
  re: RegExp;
  confidence: number;
}

const KNOWN_FORMATS: KnownFormat[] = [
  { label: 'AWS access key ID', re: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g, confidence: 0.9 },
  {
    label: 'AWS secret access key',
    re: /aws[\w.-]{0,30}(?:secret|private)[\w.-]{0,30}["']?\s*[:=]\s*["'`]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
    confidence: 0.85,
  },
  { label: 'Google API key', re: /\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/g, confidence: 0.85 },
  { label: 'Slack token', re: /\b(xox[baprs]-[0-9A-Za-z-]{10,})/g, confidence: 0.9 },
  {
    label: 'Slack webhook URL',
    re: /(https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]+\/B[0-9A-Z]+\/[0-9A-Za-z]{20,})/g,
    confidence: 0.9,
  },
  {
    label: 'GitHub token',
    re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})/g,
    confidence: 0.9,
  },
  { label: 'npm token', re: /\b(npm_[A-Za-z0-9]{36})\b/g, confidence: 0.9 },
  { label: 'Stripe secret key', re: /\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})/g, confidence: 0.9 },
  { label: 'SendGrid API key', re: /\b(SG\.[\w-]{22}\.[\w-]{43})/g, confidence: 0.9 },
  {
    label: 'JSON Web Token',
    re: /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,})/g,
    confidence: 0.75,
  },
  {
    label: 'private key',
    re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)/g,
    confidence: 0.95,
  },
  {
    label: 'password in connection URL',
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/'"`]+:([^\s@/'"`]{3,})@[^\s'"`]+/gi,
    confidence: 0.7,
  },
];

/** Names whose value is a credential (matched against the last segment of the name). */
const SECRET_NAME =
  /(pass(word|wd|phrase)?|pwd|secret|secret(or)?key|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer[_-]?token|token|credentials?|signing[_-]?key|encryption[_-]?key|session[_-]?secret)$/i;
const PUBLIC_NAME = /^(public|pub)|publishable|client[_-]?id$/i;
/** Context names that mean "this string is not a secret". */
const NON_SECRET_CONTEXT =
  /(hash|checksum|integrity|sha\d*|md5|etag|uuid|guid|id|url|uri|href|path|regex|pattern|selector|class(name)?|style|template|query|sql|label|message|text|title|placeholder|description|name|key[_-]?name|type)$/i;

const LOCKFILES = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'composer.lock',
  'Gemfile.lock',
  'poetry.lock',
  'Pipfile.lock',
  'go.sum',
]);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HASH_SHAPED = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$/i;

export function isPlaceholder(value: string): boolean {
  const v = value.trim().toLowerCase();
  if (v.length < 4) return true;
  if (
    /^(changeme|change[-_ ]?me|password|passw0rd|secret|admin|root|test|testing|example|sample|dummy|placeholder|todo|fixme|none|null|nil|undefined|true|false|default|demo|foo|bar|foobar|qwerty|letmein|token|apikey|api[-_]key)$/.test(
      v,
    )
  ) {
    return true;
  }
  if (
    /(example|changeme|placeholder|your[-_ ]?(api|secret|key|token|password|pass)|replace[-_ ]?(me|this)|insert[-_ ]?(here|your)|<[^>]+>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[a-z_]+%|xxxx|\*{3,})/.test(
      v,
    )
  ) {
    return true;
  }
  if (/^\$[a-z_]+$/.test(v) || v.startsWith('process.env')) return true;
  return /^(.)\1+$/.test(v); // aaaa, 0000
}

/** Values that are clearly not credentials even under a secret-sounding name. */
function looksNonSecret(value: string): boolean {
  return (
    /^[a-z][a-z0-9+.-]*:\/\//i.test(value) || // URL (credentials in URLs are a separate rule)
    /^[A-Z0-9_]+(\.[A-Z0-9_]+)+$/.test(value) || // i18n key LOGIN.PASSWORD
    /\s\S+\s/.test(value.trim()) || // prose
    /^(\.{0,2}\/|~\/)|\.(json|pem|key|crt|txt|ya?ml|env)$/i.test(value) || // file path
    /-----BEGIN (RSA )?PUBLIC KEY-----/.test(value) ||
    /^pk_(live|test)_/.test(value) || // Stripe publishable key
    /\.apps\.googleusercontent\.com$/.test(value) // OAuth client ID (public)
  );
}

export function shannonEntropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function isHighEntropy(s: string, o: Required<SecretsDetectorOptions>): boolean {
  if (s.length < o.minEntropyLength || s.length > 512 || /\s/.test(s)) return false;
  if (UUID.test(s) || HASH_SHAPED.test(s)) return false;
  if (/^[0-9a-f]+$/i.test(s)) return s.length >= 32 && shannonEntropy(s) >= o.hexEntropyThreshold;
  if (!/^[A-Za-z0-9+/=_-]+$/.test(s)) return false;
  if (!(/[a-z]/.test(s) && /[A-Z]/.test(s) && /\d/.test(s))) return false;
  return shannonEntropy(s) >= o.entropyThreshold;
}

interface Hit {
  path: string;
  line: number;
  value: string;
  label: string;
  confidence: number;
}

function lastSegment(name: string | undefined): string {
  return (
    (name ?? '')
      .split(/[.[\]]/)
      .filter(Boolean)
      .at(-1) ?? ''
  );
}

function isSecretName(name: string): boolean {
  return SECRET_NAME.test(name) && !PUBLIC_NAME.test(name);
}

function propertyKeyName(node: AstNode): string | undefined {
  const key = (node.raw as { key?: { type: string; name?: string; value?: string } }).key;
  return key?.type === 'Identifier' ? key.name : key?.value;
}

function literalValue(node: AstNode | undefined): string | undefined {
  if (!node) return undefined;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral') return node.value;
  return undefined;
}

/** Literal keys passed to crypto/JWT APIs: `createHmac('sha256', 'k3y')`, `jwt.sign(p, 'k3y')`. */
const KEY_ARGUMENTS: Array<{ pattern: string; index: number }> = [
  { pattern: '*.createHmac', index: 1 },
  { pattern: 'createHmac', index: 1 },
  { pattern: '*.createCipheriv', index: 1 },
  { pattern: '*.createDecipheriv', index: 1 },
  { pattern: 'jwt.sign', index: 1 },
  { pattern: 'jwt.verify', index: 1 },
  { pattern: 'jsonwebtoken.sign', index: 1 },
  { pattern: 'jsonwebtoken.verify', index: 1 },
  { pattern: 'cookieParser', index: 0 },
];

function scanAst(file: { path: string; ast: AstNode }, o: Required<SecretsDetectorOptions>): Hit[] {
  const hits: Hit[] = [];
  const credentialNodes = new Set<AstNode>();
  const add = (node: AstNode, value: string, label: string, confidence: number) => {
    hits.push({ path: file.path, line: node.loc.startLine, value, label, confidence });
  };
  const credential = (name: string | undefined, valueNode: AstNode | undefined) => {
    const value = literalValue(valueNode);
    const last = lastSegment(name);
    if (!valueNode || value === undefined || !isSecretName(last)) return;
    credentialNodes.add(valueNode);
    if (isPlaceholder(value) || looksNonSecret(value)) return;
    add(valueNode, value, `hard-coded credential "${last}"`, 0.75);
  };

  for (const n of walk(file.ast)) {
    if (n.type === 'Assignment') {
      credential(
        n.left?.type === 'Identifier' || n.left?.type === 'MemberAccess' ? n.name : undefined,
        n.right,
      );
    } else if (n.type === 'Property' && n.parent?.type === 'Object') {
      credential(propertyKeyName(n), n.children.at(-1));
    } else if (n.rawType === 'ClassProperty' || n.rawType === 'ClassPrivateProperty') {
      const raw = n.raw as { value?: unknown };
      const valueNode = n.children.find((c) => c.raw === raw.value);
      credential(propertyKeyName(n), valueNode);
    } else if (n.type === 'Call') {
      for (const { pattern, index } of KEY_ARGUMENTS) {
        if (!matchesName(n.name, pattern)) continue;
        const arg = n.arguments?.[index];
        if (!arg) continue;
        for (const v of resolveValues(arg)) {
          const value = literalValue(v);
          if (value === undefined || isPlaceholder(value)) continue;
          credentialNodes.add(v);
          add(v, value, `hard-coded key passed to ${n.name}()`, 0.85);
        }
      }
    }
  }

  // Entropy-only candidates: string literals not already judged as credentials.
  for (const n of walk(file.ast)) {
    if (n.type !== 'StringLiteral' || credentialNodes.has(n) || !n.value) continue;
    const parent = n.parent;
    if (!parent || parent.type === 'Import' || parent.rawType === 'ExportNamedDeclaration')
      continue;
    if (parent.type === 'Call' && ['require', 'import'].includes(parent.name ?? '')) continue;
    if (parent.type === 'Property' && parent.children[0] === n) continue; // object key
    if (parent.rawType === 'JSXAttribute') continue;
    const contextName =
      parent.type === 'Assignment'
        ? lastSegment(parent.name)
        : parent.type === 'Property'
          ? (propertyKeyName(parent) ?? '')
          : '';
    if (contextName && (NON_SECRET_CONTEXT.test(contextName) || PUBLIC_NAME.test(contextName)))
      continue;
    if (isPlaceholder(n.value) || looksNonSecret(n.value) || !isHighEntropy(n.value, o)) continue;
    add(n, n.value, 'high-entropy string (possible secret)', 0.45);
  }
  return hits;
}

/** `.env`, YAML, JSON, properties: `KEY=value` / `key: value` lines. */
function scanConfigLines(
  filePath: string,
  lines: string[],
  o: Required<SecretsDetectorOptions>,
): Hit[] {
  const hits: Hit[] = [];
  const LINE =
    /^\s*(?:export\s+)?["']?([A-Za-z0-9_.-]+)["']?\s*[:=]\s*["']?([^"'\s#,]+)["']?\s*,?\s*(?:#.*)?$/;
  lines.forEach((line, i) => {
    const m = LINE.exec(line);
    if (!m) return;
    const [, key = '', value = ''] = m;
    if (isPlaceholder(value) || looksNonSecret(value)) return;
    if (isSecretName(lastSegment(key))) {
      hits.push({
        path: filePath,
        line: i + 1,
        value,
        label: `hard-coded credential "${key}"`,
        confidence: 0.75,
      });
    } else if (!NON_SECRET_CONTEXT.test(key) && isHighEntropy(value, o)) {
      hits.push({
        path: filePath,
        line: i + 1,
        value,
        label: 'high-entropy string (possible secret)',
        confidence: 0.45,
      });
    }
  });
  return hits;
}

function scanKnownFormats(filePath: string, lines: string[]): Hit[] {
  const hits: Hit[] = [];
  lines.forEach((line, i) => {
    for (const { label, re, confidence } of KNOWN_FORMATS) {
      re.lastIndex = 0;
      for (const m of line.matchAll(re)) {
        const value = m[1] ?? m[0];
        if (label === 'private key') {
          hits.push({ path: filePath, line: i + 1, value, label, confidence });
          continue;
        }
        if (isPlaceholder(value)) continue;
        hits.push({ path: filePath, line: i + 1, value, label, confidence });
      }
    }
  });
  return hits;
}

/** Snippet with every secret value on the line replaced by its redacted form. */
function redactedSnippet(ctx: DetectionContext, hit: Hit, others: Hit[]): string {
  let snippet = ctx.snippet(hit.path, hit.line);
  // A PEM block's body follows its header (often on the same line via \n escapes).
  snippet = snippet.replace(
    /(-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g,
    '$1…[redacted]…$2',
  );
  const values = others
    .filter((h) => h.path === hit.path && h.line === hit.line)
    .map((h) => h.value);
  for (const value of [...new Set(values)].sort((a, b) => b.length - a.length)) {
    if (value.startsWith('-----BEGIN')) continue;
    snippet = snippet.split(value).join(redact(value));
  }
  return snippet;
}

export function createSecretsDetector(options: SecretsDetectorOptions = {}): Detector {
  const o: Required<SecretsDetectorOptions> = {
    entropyThreshold: options.entropyThreshold ?? 4.5,
    hexEntropyThreshold: options.hexEntropyThreshold ?? 3.5,
    minEntropyLength: options.minEntropyLength ?? 20,
  };

  return {
    id: 'A5-hardcoded-secrets',
    title: 'Hard-coded secret',
    owaspCategory: CATEGORY,
    cwe: 'CWE-798',
    technique: 'pattern',
    explanation:
      'A credential (password, API key, token, or private key) is written directly in the ' +
      'source. Anyone with access to the code (other developers, a leaked repository, a ' +
      'build artifact) can use it to impersonate the application, and it cannot be rotated ' +
      'without a code change. Rotate it now: treat it as compromised.',
    fixSuggestion:
      'Move the value to an environment variable or a secret manager (Vault, AWS Secrets ' +
      'Manager, …), rotate the exposed credential, and never ship secrets to the client.',

    run(ctx) {
      const paths = new Set<string>(ctx.sourceFiles.map((f) => f.path));
      for (const p of ctx.configPaths) {
        if (p.category === 'env' || p.category === 'key-material') paths.add(p.path);
      }

      const hits: Hit[] = [];
      for (const filePath of paths) {
        if (isTestPath(filePath) || LOCKFILES.has(path.posix.basename(filePath))) continue;
        const text = ctx.readText(filePath);
        if (text === null) continue;
        const lines = text.split('\n');
        hits.push(...scanKnownFormats(filePath, lines));
        const parsed = ctx.getParsedFile(filePath);
        if (parsed?.ast) {
          hits.push(...scanAst({ path: filePath, ast: parsed.ast }, o));
        } else if (!/\.(md|markdown|html?|css|scss|svg)$/i.test(filePath)) {
          hits.push(
            ...scanConfigLines(
              filePath,
              lines.map((l) => l.replace(/\r$/, '')),
              o,
            ),
          );
        }
      }

      // One finding per (file, line, value): keep the most specific rule.
      const best = new Map<string, Hit>();
      for (const h of hits) {
        const key = `${h.path}\u0000${h.line}\u0000${h.value}`;
        const prev = best.get(key);
        if (!prev || h.confidence > prev.confidence) best.set(key, h);
      }

      const clientCache = new Map<string, boolean>();
      return [...best.values()].map((h): RawFinding => {
        let client = clientCache.get(h.path);
        if (client === undefined) {
          client = isClientSide(ctx, h.path);
          clientCache.set(h.path, client);
        }
        const shown = h.label === 'private key' ? h.value : redact(h.value);
        return {
          detectorId: 'A5-hardcoded-secrets',
          owaspCategory: CATEGORY,
          severity: client ? 'critical' : 'high',
          confidence: h.confidence,
          filePath: h.path,
          lineStart: h.line,
          lineEnd: h.line,
          snippet: redactedSnippet(ctx, h, hits),
          evidence:
            `${h.label}: ${shown}` +
            (client ? ' (in client-side code: shipped to every browser)' : ''),
        };
      });
    },
  };
}

export const hardcodedSecrets = registerDetector(createSecretsDetector());
