import { rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FAKE, materializeSecretsProject } from '../../../test/secrets-project.js';
import type { ParsedFile } from '../../ast/types.js';
import { parseSourceFiles } from '../../parse-project.js';
import { ProfilerService } from '../../profiler/profiler.js';
import { createDetectionContext } from '../context.js';
import { dedupeFindings } from '../dedupe.js';
import { DetectionEngine } from '../engine.js';
import type { FindingDraft } from '../types.js';
import { isPlaceholder, shannonEntropy } from './a5-hardcoded-secrets.js';
import { createDefaultDetectorRegistry } from './index.js';

async function scan(root: string): Promise<FindingDraft[]> {
  const profile = await new ProfilerService().profile(root);
  const files: ParsedFile[] = [];
  for await (const f of parseSourceFiles(root, profile)) files.push(f);
  const result = await new DetectionEngine(createDefaultDetectorRegistry()).run(
    createDetectionContext({ rootDir: root, profile, files }),
  );
  expect(result.detectorErrors).toEqual([]);
  return dedupeFindings(result.findings);
}

const by = (findings: FindingDraft[], id: string, path?: string, line?: number) =>
  findings.filter(
    (f) =>
      f.detectorId === id &&
      (path === undefined || f.filePath === path) &&
      (line === undefined || f.lineStart === line),
  );

// ---------------------------------------------------------------------------
// A5 — hardcoded secrets
// ---------------------------------------------------------------------------

describe('A5-hardcoded-secrets', () => {
  let root: string;
  let findings: FindingDraft[];
  const secrets = (path?: string, line?: number) =>
    by(findings, 'A5-hardcoded-secrets', path, line);

  beforeAll(async () => {
    root = await materializeSecretsProject();
    findings = await scan(root);
  });
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('flags a hard-coded AWS key in a server file as high', () => {
    const [f] = secrets('server/config/aws.ts', 2);
    expect(f).toMatchObject({
      owaspCategory: 'A04:2025-Cryptographic Failures',
      severity: 'high',
      confidence: 0.9,
    });
    expect(f!.evidence[0]).toBe('AWS access key ID: AKIA…[redacted, 20 chars]');
    expect(f!.fixSuggestion).toMatch(/environment variable|secret manager/i);
    expect(f!.fixSuggestion).toMatch(/rotate/i);
  });

  it('flags the same AWS key in a front-end (Angular) file as critical', () => {
    const [f] = secrets('frontend/src/app/upload/aws-upload.service.ts');
    expect(f).toMatchObject({ severity: 'critical', confidence: 0.9, lineStart: 5 });
    expect(f!.evidence[0]).toContain('shipped to every browser');
  });

  it("flags Juice Shop's exposed testing password in the login component as critical (#14)", () => {
    const [f] = secrets('frontend/src/app/login/login.component.ts');
    expect(f).toMatchObject({ severity: 'critical', lineStart: 6 });
    expect(f!.evidence[0]).toContain('"testingPassword"');
    // The public OAuth client ID and the username are not secrets.
    expect(secrets('frontend/src/app/login/login.component.ts')).toHaveLength(1);
  });

  it('marks secrets in a served static dir as critical', () => {
    expect(secrets('public/js/chat-widget.js').map((f) => f.severity)).toEqual(['critical']);
  });

  it('detects private keys, JWTs, committed .env credentials, and passwords in URLs', () => {
    expect(secrets('server/lib/keys.ts').map((f) => [f.lineStart, f.confidence])).toEqual([
      [1, 0.95],
      [2, 0.75],
    ]);
    expect(secrets('config/.env.production').map((f) => f.lineStart)).toEqual([1, 3]);
    expect(secrets('server/config/aws.ts', 3)[0]!.evidence[0]).toContain('"secretAccessKey"');
  });

  it('never exposes a full secret value in evidence or snippets', () => {
    const all = JSON.stringify(secrets());
    for (const value of [
      FAKE.awsKeyId,
      FAKE.awsSecret,
      FAKE.slackToken,
      FAKE.jwt,
      FAKE.pemBody,
      FAKE.dbPassword,
      FAKE.envPassword,
      'IamUsedForTesting',
    ]) {
      expect(all).not.toContain(value);
    }
    expect(secrets('server/lib/keys.ts', 1)[0]!.snippet).toContain('PRIVATE KEY-----…[redacted]…');
  });

  it("suppresses password = 'changeme', placeholders, UUIDs, hashes, public keys, and labels", () => {
    expect(secrets('server/config/safe.ts')).toEqual([]);
  });

  it('skips test files and lockfiles', () => {
    expect(secrets('tests/login.spec.ts')).toEqual([]);
    expect(secrets('package-lock.json')).toEqual([]);
  });

  it('produces exactly the expected findings', () => {
    expect(
      secrets()
        .map((f) => `${f.severity} ${f.filePath}:${f.lineStart}`)
        .sort(),
    ).toEqual([
      'critical frontend/src/app/login/login.component.ts:6',
      'critical frontend/src/app/upload/aws-upload.service.ts:5',
      'critical public/js/chat-widget.js:1',
      'high config/.env.production:1',
      'high config/.env.production:3',
      'high server/config/aws.ts:2',
      'high server/config/aws.ts:3',
      'high server/lib/keys.ts:1',
      'high server/lib/keys.ts:2',
    ]);
  });
});

describe('secret heuristics', () => {
  it('recognizes placeholders', () => {
    for (const v of [
      'changeme',
      'your-key-here',
      'xxxxxxxx',
      'EXAMPLE_TOKEN',
      '${API_KEY}',
      '<secret>',
      '****',
    ]) {
      expect(isPlaceholder(v), v).toBe(true);
    }
    expect(isPlaceholder('IamUsedForTesting')).toBe(false);
  });

  it('computes Shannon entropy', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
    expect(shannonEntropy('abcd')).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// A6 — weak crypto
// ---------------------------------------------------------------------------

describe('A6-weak-crypto', () => {
  const ROOT = fileURLToPath(new URL('../../../test/fixtures/crypto', import.meta.url));
  let findings: FindingDraft[];
  const crypto = (path?: string, line?: number) => by(findings, 'A6-weak-crypto', path, line);

  beforeAll(async () => {
    findings = await scan(ROOT);
  });

  it("flags crypto.createHash('md5').update(pw) on a password as high", () => {
    const [f] = crypto('server/routes/changePassword.js', 7);
    expect(f).toMatchObject({
      owaspCategory: 'A04:2025-Cryptographic Failures',
      severity: 'high',
      confidence: 0.9,
    });
    expect(f!.evidence[0]).toContain('MD5 (fast, unsalted) used to hash a password: `pw`');
    expect(f!.fixSuggestion).toMatch(/argon2|bcrypt/);
  });

  it('flags even SHA-256 when it is used to hash a password (no salt, too fast)', () => {
    expect(crypto('server/routes/changePassword.js', 8)[0]).toMatchObject({ severity: 'high' });
  });

  it('follows Juice Shop security.hash() to its caller with req.body.password (#39)', () => {
    const [f] = crypto('server/lib/insecurity.ts', 5);
    expect(f).toMatchObject({ severity: 'high', confidence: 0.85 });
    expect(f!.evidence[0]).toContain(
      'hash() is called with `req.body.password` at server/routes/login.ts:7',
    );
  });

  it('suppresses MD5/SHA-1 used for file checksums, ETags, and cache keys', () => {
    expect(crypto('server/lib/checksum.js')).toEqual([]);
  });

  it('reports MD5/SHA-1 with a non-secret input only as low severity', () => {
    expect(crypto('server/lib/request-id.js').map((f) => [f.severity, f.confidence])).toEqual([
      ['low', 0.3],
    ]);
  });

  it('flags an encrypt() that only base64-encodes as medium', () => {
    const lines = crypto('server/lib/encryption.js').map((f) => [f.lineStart, f.severity]);
    expect(lines).toEqual([
      [3, 'medium'], // encrypt(): toString('base64')
      [7, 'medium'], // decrypt(): Buffer.from(_, 'base64')
      [10, 'medium'], // encryptedToken: btoa(...)
    ]);
  });

  it('flags z85 "encrypted" coupons (#40)', () => {
    expect(crypto('server/lib/insecurity.ts').map((f) => [f.lineStart, f.severity])).toEqual([
      [5, 'high'],
      [10, 'medium'],
      [14, 'medium'],
    ]);
  });

  it('flags createCipher, 3DES, and ECB but not AES-GCM', () => {
    expect(crypto('server/lib/legacy-cipher.js').map((f) => f.lineStart)).toEqual([5, 10, 15]);
  });

  it('does not flag bcrypt, argon2, scrypt, or pbkdf2', () => {
    expect(crypto('server/lib/passwords.js')).toEqual([]);
  });

  it('applies the pattern rule to Python password hashing only', () => {
    expect(crypto('legacy/auth.py').map((f) => [f.lineStart, f.severity])).toEqual([[6, 'high']]);
  });

  it('also reports the hard-coded HMAC key in insecurity.ts (A5)', () => {
    const [f] = by(findings, 'A5-hardcoded-secrets', 'server/lib/insecurity.ts');
    expect(f!.evidence[0]).toBe(
      'hard-coded key passed to crypto.createHmac(): pa4q…[redacted, 24 chars]',
    );
  });
});
