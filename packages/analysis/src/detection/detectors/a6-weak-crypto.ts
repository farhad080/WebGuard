import { findAll, matchesName, textOf } from '../../ast/queries.js';
import { parameterNames, resolveIdentifier, resolveValues, traceTaint } from '../../ast/taint.js';
import type { AstNode, ParsedFile } from '../../ast/types.js';
import { registerDetector } from '../registry.js';
import type { DetectionContext, RawFinding } from '../types.js';
import { enclosingFunction, findingAt, parsedFiles, shorten } from './shared.js';

/**
 * A6 — Weak cryptography (AST + pattern).
 *
 * Objective: find cryptography that doesn't protect what it's used for.
 *
 * Rules:
 *  1. Password hashing without a salted, slow KDF: `createHash(any)` / `md5()` / `sha1()` /
 *     `CryptoJS.MD5()` whose input traces to a password-like value (a variable or field named
 *     password/pwd/secret/pin/…, in the same function or, one level up, at the call sites of
 *     the hashing helper). High. Juice Shop #39: `security.hash(req.body.password)` → MD5.
 *  2. Broken ciphers: `createCipher()` (deprecated: no IV, MD5 key derivation), DES / 3DES /
 *     RC4 / RC2 / Blowfish / ECB mode in `createCipheriv()`, CryptoJS DES/RC4/TripleDES/ECB. High.
 *  3. Encoding used as encryption: base64 / hex / z85 / rot13 / btoa / atob inside a function
 *     named encrypt/decrypt/cipher/obfuscate/coupon, or assigned to something named
 *     encrypted/cipher. Medium. Juice Shop #40: coupons "encrypted" with z85.
 *  4. Pattern rule for other languages: `hashlib.md5(` / `MessageDigest.getInstance("MD5")` /
 *     PHP `md5(` on a line that handles a password. High.
 *
 * MD5/SHA-1 off the secret path: checksums, ETags, cache keys and file digests are dropped;
 * other uses with an unknown input are reported as low severity (confidence 0.3).
 */

const CATEGORY = 'A04:2025-Cryptographic Failures' as const;

const PASSWORDISH = /(pass(word|wd|phrase)?|pwd|secret|credentials?)$/i;
const SHORT_PASSWORDISH = /(^|[._])(pw|pin|otp)$/i;
const isPasswordish = (n: AstNode): boolean => {
  if (n.type !== 'Identifier' && n.type !== 'MemberAccess') return false;
  const name = n.name ?? '';
  return PASSWORDISH.test(name) || SHORT_PASSWORDISH.test(name);
};

const WEAK_HASHES = new Set(['md5', 'md4', 'md2', 'sha1', 'sha-1', 'ripemd', 'ripemd160']);
const HASH_LIBRARY_CALLS: Array<{ pattern: string; algorithm: string }> = [
  { pattern: 'md5', algorithm: 'md5' },
  { pattern: 'sha1', algorithm: 'sha1' },
  { pattern: 'sha256', algorithm: 'sha256' },
  { pattern: 'CryptoJS.MD5', algorithm: 'md5' },
  { pattern: 'CryptoJS.SHA1', algorithm: 'sha1' },
  { pattern: 'CryptoJS.SHA256', algorithm: 'sha256' },
  { pattern: 'CryptoJS.SHA512', algorithm: 'sha512' },
];
const WEAK_CIPHER =
  /(^|[-_])(des|des3|des-ede3?|3des|rc4|rc2|bf|blowfish|idea|cast5?|seed)([-_]|$)|ecb/i;
const CRYPTOJS_WEAK = [
  'CryptoJS.DES.encrypt',
  'CryptoJS.TripleDES.encrypt',
  'CryptoJS.RC4.encrypt',
  'CryptoJS.Rabbit.encrypt',
];

const CHECKSUM_CONTEXT =
  /checksum|etag|cache|fingerprint|integrity|digest|sri|filehash|contenthash|hashkey|cachekey|eTag|hash$/i;
const FILE_INPUT = [
  'fs.readFileSync',
  'fs.readFile',
  'readFileSync',
  '*.readFile',
  'fs.createReadStream',
];

const ENCODING_CALLS = [
  'btoa', 'atob', 'window.btoa', 'window.atob', 'base64.encode', 'base64.decode', 'Base64.encode',
  'Base64.decode', 'base64url.encode', 'base64url.decode', 'z85.encode', 'z85.decode', 'rot13',
  'str_rot13', 'CryptoJS.enc.Base64.stringify', 'CryptoJS.enc.Base64.parse', 'hex.encode', 'hex.decode',
]; // prettier-ignore
const ENCRYPTION_CONTEXT = /(en|de)crypt|cipher|obfusc|coupon/i;

const EXPLAIN = {
  password:
    'Passwords are hashed with a fast, unsalted hash. Fast hashes (MD5, SHA-1, even SHA-256) ' +
    'can be brute-forced at billions of guesses per second on a GPU, and without a salt, ' +
    'identical passwords share a hash and precomputed rainbow tables crack them instantly. ' +
    'MD5 and SHA-1 are additionally broken. A leaked user table therefore exposes most passwords.',
  cipher:
    'A broken or obsolete cipher is used. DES/3DES and RC4 are breakable, ECB mode encrypts ' +
    'identical blocks identically (leaking patterns in the plaintext), and createCipher() ' +
    'derives the key with a single MD5 pass and no IV. Encrypted data should be treated as ' +
    'readable by an attacker.',
  encoding:
    'Encoding (base64, hex, z85, rot13) is used where encryption is expected. Encoding has no ' +
    'key: anyone can decode it instantly, so "encrypted" values such as coupons or tokens can ' +
    'be read and forged (e.g. Juice Shop coupons are just z85-encoded text).',
  weakHash:
    'MD5/SHA-1 are cryptographically broken (practical collisions). This use does not appear ' +
    'to involve a secret; it is fine for non-security checksums, but must not be used for ' +
    'signatures, integrity against attackers, or anything secret.',
};

const FIX = {
  password:
    'Hash passwords with argon2id (or bcrypt / scrypt) and a per-user salt, e.g. ' +
    'argon2.hash(password); re-hash existing users on next login.',
  cipher:
    'Use AES-256-GCM via crypto.createCipheriv with a random 12-byte IV per message and a key ' +
    'from a KDF or secret manager; never ECB, DES, RC4, or createCipher().',
  encoding:
    'Use real authenticated encryption (AES-256-GCM) with a server-side key, or sign the value ' +
    '(HMAC-SHA-256) if it only needs to be tamper-proof.',
  weakHash:
    'Use SHA-256 or better where a cryptographic hash is needed; keep MD5/SHA-1 only for ' +
    'non-security checksums.',
};

function literal(node: AstNode | undefined): string | undefined {
  if (!node) return undefined;
  for (const v of resolveValues(node)) {
    if (v.type === 'StringLiteral') return v.value;
  }
  return undefined;
}

/** For `crypto.createHash(alg)`, the value(s) fed in via `.update(x)` (chained or via a variable). */
function hashInputs(createHash: AstNode): AstNode[] {
  const inputs: AstNode[] = [];
  // createHash('md5').update(x)
  const member = createHash.parent;
  if (
    member?.type === 'MemberAccess' &&
    member.property === 'update' &&
    member.parent?.type === 'Call'
  ) {
    const arg = member.parent.arguments?.[0];
    if (arg) inputs.push(arg);
  }
  // const h = createHash('md5'); h.update(x)
  const decl = createHash.parent;
  if (
    decl?.type === 'Assignment' &&
    decl.right === createHash &&
    decl.left?.type === 'Identifier'
  ) {
    const varName = decl.left.name;
    const scope = enclosingFunction(createHash)?.fn ?? root(createHash);
    for (const call of findAll(scope, (n) => n.type === 'Call' && n.name === `${varName}.update`)) {
      const arg = call.arguments?.[0];
      if (arg) inputs.push(arg);
    }
  }
  return inputs;
}

function root(node: AstNode): AstNode {
  let n = node;
  while (n.parent) n = n.parent;
  return n;
}

/** Name of what the result is stored in: `const checksum = createHash(...)...digest()`. */
function resultTargetName(node: AstNode): string | undefined {
  for (let p = node.parent; p; p = p.parent) {
    if (p.type === 'Assignment') return p.name?.split('.').at(-1);
    if (p.type === 'Property') return (p.raw as { key?: { name?: string } }).key?.name;
    if (p.type === 'Return' || p.type === 'Function' || p.type === 'Block') return undefined;
  }
  return undefined;
}

interface SecretPath {
  evidence: string;
  confidence: number;
}

/**
 * Does `input` carry a password? Checked in the same function first, then, if the input is a
 * parameter of a named helper (`hash(data)`), at the helper's call sites across the project.
 */
function secretPath(
  ctx: DetectionContext,
  file: ParsedFile,
  input: AstNode,
): SecretPath | undefined {
  const direct = traceTaint(input, { isSource: isPasswordish });
  if (direct.tainted) {
    const src = direct.flows[0]!.source;
    return {
      evidence: `\`${shorten(textOf(file, src), 60)}\``,
      confidence: direct.direct ? 0.9 : 0.75,
    };
  }
  const fnInfo = enclosingFunction(input);
  if (fnInfo?.name && PASSWORDISH.test(fnInfo.name)) {
    return { evidence: `inside ${fnInfo.name}()`, confidence: 0.8 };
  }

  // One level of inter-procedural tracing: input is parameter #i of helper `name`.
  const base = input.type === 'Identifier' ? input : undefined;
  const resolution = base ? resolveIdentifier(base) : undefined;
  if (!fnInfo?.name || resolution?.kind !== 'parameter' || resolution.fn !== fnInfo.fn)
    return undefined;
  const index = parameterNames(fnInfo.fn).indexOf(base!.name!);
  if (index < 0) return undefined;
  const helper = fnInfo.name;
  const moduleName = file.path
    .split('/')
    .at(-1)!
    .replace(/\.[cm]?[jt]sx?$/, '');
  /** `hash(x)` in the same file / importing this module, or `security.hash(x)` via an import. */
  const callsHelper = (other: ParsedFile, call: AstNode): boolean => {
    if (call.name === helper) {
      return (
        other === file ||
        new RegExp(`\\b${helper}\\b[^;\\n]*['"][^'"]*\\b${moduleName}['"]`).test(other.sourceText)
      );
    }
    if (!matchesName(call.name, `*.${helper}`)) return false;
    const receiver = call.name!.split('.').slice(0, -1).join('.');
    if (!/^[A-Za-z_$][\w$]*$/.test(receiver)) return false;
    return new RegExp(
      `(import\\s+\\*\\s+as\\s+${receiver}\\s+from|import\\s+${receiver}\\s+from|(const|let|var)\\s+${receiver}\\s*=\\s*require\\()\\s*['"][^'"]*\\b${moduleName}['"]`,
    ).test(other.sourceText);
  };
  for (const other of parsedFiles(ctx)) {
    for (const call of findAll(other, (n) => n.type === 'Call' && callsHelper(other, n))) {
      const arg = call.arguments?.[index];
      if (!arg) continue;
      const t = traceTaint(arg, { isSource: isPasswordish });
      if (t.tainted) {
        return {
          evidence: `${helper}() is called with \`${shorten(textOf(other, arg), 60)}\` at ${other.path}:${call.loc.startLine}`,
          confidence: 0.85,
        };
      }
    }
  }
  return undefined;
}

function isChecksumUse(hashCall: AstNode, inputs: AstNode[]): boolean {
  const target = resultTargetName(hashCall);
  if (target && CHECKSUM_CONTEXT.test(target)) return true;
  const fn = enclosingFunction(hashCall)?.name;
  if (fn && CHECKSUM_CONTEXT.test(fn)) return true;
  return inputs.some((input) =>
    resolveValues(input).some(
      (v) => v.type === 'Call' && FILE_INPUT.some((p) => matchesName(v.name, p)),
    ),
  );
}

export const weakCrypto = registerDetector({
  id: 'A6-weak-crypto',
  title: 'Weak cryptography',
  owaspCategory: CATEGORY,
  cwe: 'CWE-327',
  technique: 'ast',
  explanation: EXPLAIN.cipher,
  fixSuggestion: FIX.cipher,

  run(ctx) {
    const findings: RawFinding[] = [];
    const push = (
      file: ParsedFile,
      node: AstNode,
      kind: keyof typeof EXPLAIN,
      severity: RawFinding['severity'],
      confidence: number,
      evidence: string,
    ) =>
      findings.push(
        findingAt(ctx, file, node, {
          detectorId: 'A6-weak-crypto',
          owaspCategory: CATEGORY,
          severity,
          confidence,
          evidence,
          explanation: EXPLAIN[kind],
          fixSuggestion: FIX[kind],
          cwe: kind === 'password' ? 'CWE-916' : kind === 'encoding' ? 'CWE-261' : 'CWE-327',
        }),
      );

    for (const file of parsedFiles(ctx)) {
      for (const call of findAll(file, (n) => n.type === 'Call')) {
        const name = call.name ?? '';
        const args = call.arguments ?? [];

        // ---- Hashing ----
        let algorithm: string | undefined;
        let inputs: AstNode[] = [];
        if (matchesName(name, '*.createHash') || name === 'createHash') {
          algorithm = literal(args[0])?.toLowerCase();
          inputs = hashInputs(call);
        } else {
          const lib = HASH_LIBRARY_CALLS.find((h) => name === h.pattern);
          if (lib && args[0]) {
            algorithm = lib.algorithm;
            inputs = [args[0]];
          }
        }
        if (algorithm) {
          const secret = inputs.map((i) => secretPath(ctx, file, i)).find(Boolean);
          const where = `${name}(${algorithm ? `'${algorithm}'` : ''})`;
          if (secret) {
            push(
              file,
              call,
              'password',
              'high',
              secret.confidence,
              `${algorithm.toUpperCase()} (fast, unsalted) used to hash a password: ${secret.evidence} → ${where}`,
            );
          } else if (WEAK_HASHES.has(algorithm) && !isChecksumUse(call, inputs)) {
            push(
              file,
              call,
              'weakHash',
              'low',
              0.3,
              `${algorithm.toUpperCase()} via ${where}; input does not trace to a secret`,
            );
          }
          continue;
        }

        // ---- Ciphers ----
        if (
          matchesName(name, '*.createCipher') ||
          matchesName(name, '*.createDecipher') ||
          name === 'createCipher'
        ) {
          push(
            file,
            call,
            'cipher',
            'high',
            0.9,
            `${name}() is deprecated: MD5-based key derivation and no IV`,
          );
          continue;
        }
        if (matchesName(name, '*.createCipheriv') || matchesName(name, '*.createDecipheriv')) {
          const alg = literal(args[0]);
          if (alg && WEAK_CIPHER.test(alg)) {
            push(file, call, 'cipher', 'high', 0.9, `weak cipher "${alg}" in ${name}()`);
          }
          continue;
        }
        if (CRYPTOJS_WEAK.some((p) => name === p)) {
          push(
            file,
            call,
            'cipher',
            'high',
            0.9,
            `weak cipher ${name.split('.')[1]} via ${name}()`,
          );
          continue;
        }

        // ---- Encoding used as encryption ----
        const isEncoding =
          ENCODING_CALLS.some((p) => matchesName(name, p)) ||
          (call.callee?.property === 'toString' &&
            /^(base64|base64url|hex)$/.test(literal(args[0]) ?? '')) ||
          (name === 'Buffer.from' && /^(base64|base64url|hex)$/.test(literal(args[1]) ?? ''));
        if (isEncoding) {
          const fn = enclosingFunction(call)?.name;
          const target = resultTargetName(call);
          const context =
            fn && ENCRYPTION_CONTEXT.test(fn)
              ? `${fn}()`
              : target && ENCRYPTION_CONTEXT.test(target)
                ? `"${target}"`
                : undefined;
          if (context) {
            push(
              file,
              call,
              'encoding',
              'medium',
              0.75,
              `\`${shorten(textOf(file, call), 60)}\` is encoding, not encryption, yet used as ${context}`,
            );
          }
        }
      }

      // CryptoJS mode: CryptoJS.mode.ECB
      for (const m of findAll(
        file,
        (n) => n.type === 'MemberAccess' && n.name === 'CryptoJS.mode.ECB',
      )) {
        push(file, m, 'cipher', 'high', 0.85, 'CryptoJS.mode.ECB leaks plaintext patterns');
      }
    }

    // ---- Pattern rule for files without a parser (Python, PHP, Java, ...) ----
    const WEAK_HASH_LINE =
      /hashlib\.(md5|sha1)\s*\(|MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"\s*\)|\b(md5|sha1)\s*\(\s*\$/i;
    for (const source of ctx.sourceFiles) {
      if (
        ctx.getParsedFile(source.path) ||
        !['python', 'php', 'java', 'ruby', 'go', 'csharp'].includes(source.language)
      )
        continue;
      const text = ctx.readText(source.path);
      if (!text) continue;
      text.split('\n').forEach((line, i) => {
        if (!WEAK_HASH_LINE.test(line) || !/pass(word|wd)?|pwd/i.test(line)) return;
        findings.push({
          detectorId: 'A6-weak-crypto',
          owaspCategory: CATEGORY,
          severity: 'high',
          confidence: 0.6,
          filePath: source.path,
          lineStart: i + 1,
          lineEnd: i + 1,
          snippet: ctx.snippet(source.path, i + 1),
          evidence: `fast hash applied to a password: ${shorten(line, 80)}`,
          explanation: EXPLAIN.password,
          fixSuggestion: FIX.password,
          cwe: 'CWE-916',
        });
      });
    }
    return findings;
  },
});
