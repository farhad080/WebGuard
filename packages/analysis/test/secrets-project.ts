import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

/**
 * Builds the hard-coded-secrets fixture project in a temp dir.
 *
 * The fake secrets are assembled from pieces at runtime so that no complete, provider-shaped
 * token is committed to this repository (it would trip GitHub push protection and other
 * scanners, including WebGuard itself). None of these values are real credentials.
 */
const j = (...parts: string[]) => parts.join('');

export const FAKE = {
  awsKeyId: j('AKIA', '2E0A8F3B', '244C9986'),
  awsSecret: j('q8Hx3vR2pL9mN4tK', '7wZ1cB6dF0gJ5sY2', 'aE8uI3oW'),
  slackToken: j('xoxb-', '4815162342', '-108-', 'fAkEsLaCkToKeN0rlyX'),
  jwt: j(
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    '.',
    'eyJzdWIiOiJzZXJ2aWNlLWFjY291bnQiLCJyb2xlIjoiYWRtaW4ifQ',
    '.',
    'c2lnbmF0dXJlLWZvci10ZXN0aW5nLW9ubHktMTIz',
  ),
  pemHeader: j('-----BEGIN RSA ', 'PRIVATE KEY-----'),
  pemFooter: j('-----END RSA ', 'PRIVATE KEY-----'),
  pemBody: j(
    'MIICXAIBAAKBgQDNwqLEe9wgTXCbC7',
    '+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa',
  ),
  dbPassword: j('Pr0d', 'DbPa55'),
  envPassword: j('Sup3r', 'S3cret', 'Passw0rd'),
};

export const SECRETS_FILES: Record<string, string> = {
  // AWS key in a server file → high
  'server/config/aws.ts': [
    'export const awsConfig = {',
    `  accessKeyId: '${FAKE.awsKeyId}',`,
    `  secretAccessKey: '${FAKE.awsSecret}',`,
    "  region: 'eu-west-1',",
    '}',
    '',
  ].join('\n'),

  // The same AWS key in an Angular service → critical (shipped to the browser)
  'frontend/src/app/upload/aws-upload.service.ts': [
    "import { Injectable } from '@angular/core'",
    '',
    "@Injectable({ providedIn: 'root' })",
    'export class AwsUploadService {',
    `  private readonly accessKeyId = '${FAKE.awsKeyId}'`,
    '}',
    '',
  ].join('\n'),

  // Juice Shop #14 "Exposed credentials": testing account in the login component
  'frontend/src/app/login/login.component.ts': [
    "import { Component } from '@angular/core'",
    '',
    "@Component({ selector: 'app-login', templateUrl: './login.component.html' })",
    'export class LoginComponent {',
    "  public testingUsername = 'testing@juice-sh.op'",
    "  public testingPassword = 'IamUsedForTesting'",
    "  public clientId = '1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.com'",
    '}',
    '',
  ].join('\n'),

  // Served static file → critical
  'public/js/chat-widget.js': [
    `const SLACK_TOKEN = '${FAKE.slackToken}';`,
    "window.chat = { connect: () => fetch('/chat', { headers: { 'X-Slack': SLACK_TOKEN } }) };",
    '',
  ].join('\n'),

  // PEM private key in a one-line string (as in Juice Shop lib/insecurity.ts) and a JWT
  'server/lib/keys.ts': [
    `const privateKey = '${FAKE.pemHeader}\\r\\n${FAKE.pemBody}\\r\\n${FAKE.pemFooter}'`,
    `export const serviceToken = '${FAKE.jwt}'`,
    'export { privateKey }',
    '',
  ].join('\n'),

  // Committed env file + password in a connection URL
  'config/.env.production': [
    `DATABASE_PASSWORD=${FAKE.envPassword}`,
    'API_KEY=changeme',
    `DATABASE_URL=postgres://app:${FAKE.dbPassword}@db.internal:5432/app`,
    'LOG_LEVEL=info',
    '',
  ].join('\n'),

  // SAFE: nothing in this file should be reported
  'server/config/safe.ts': [
    "export const password = 'changeme'",
    'export const apiKey = process.env.API_KEY',
    "export const secret = 'your-secret-here'",
    "export const requestId = '3fa85f64-5717-4562-b3fc-2c963f66afa6'",
    "export const emptyFileMd5 = 'd41d8cd98f00b204e9800998ecf8427e'",
    "export const passwordLabel = 'Enter your password'",
    "export const labels = { password: 'LOGIN.PASSWORD', token: '{{ token }}' }",
    "export const input = { type: 'password', name: 'password' }",
    "export const publicKey = '-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GN'",
    "export const stripePublishable = 'pk_live_51HxAbCdEfGhIjKlMnOpQrStUv'",
    "export const integrity = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC'",
    "export const keyFile = './keys/private.pem'",
    "export const exampleKey = 'AKIAIOSFODNN7EXAMPLE'",
    '',
  ].join('\n'),

  // Test code: real-looking secrets are expected here and skipped
  'tests/login.spec.ts': "const password = 'R3alLooking!Passw0rd'\nexport { password }\n",

  // Lockfile integrity hashes: never secrets
  'package-lock.json': JSON.stringify(
    {
      name: 'secrets-fixture',
      lockfileVersion: 3,
      packages: {
        'node_modules/express': {
          integrity: 'sha512-a3B9xK2mN8pQ4rT7vW1yZ5cE0gH6jL3oS9uI2fD4kM7nP1qR8tV5wX0zA6bC3eF9',
        },
      },
    },
    null,
    2,
  ),
};

export async function materializeSecretsProject(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webguard-secrets-'));
  for (const [rel, content] of Object.entries(SECRETS_FILES)) {
    const file = path.join(root, ...rel.split('/'));
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, content);
  }
  return root;
}
