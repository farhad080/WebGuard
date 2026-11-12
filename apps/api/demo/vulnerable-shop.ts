import { buildZip } from '../test/zip-writer.js';

/**
 * "Acme Shop" — a deliberately vulnerable demo project used by the seed script, the demo
 * flow, and the end-to-end test. It is SOURCE ONLY: WebGuard never runs it, and you never
 * should either.
 *
 * It exercises: SQL injection, reflected XSS, a hardcoded secret, weak password hashing,
 * a vulnerable dependency and a typosquatted one, and server misconfiguration.
 *
 * The fake secret is assembled at runtime so no key-shaped literal is committed to git
 * (secret scanners / push protection would rightly flag it).
 */
const join = (...parts: string[]) => parts.join('');
export const DEMO_FAKE_STRIPE_KEY = join('sk_', 'live_', 'D3m0', 'AcmeShop', 'N0tR3al', 'K3y2026x');

export const DEMO_PROJECT_NAME = 'Acme Shop (demo)';

/** Categories the demo is expected to produce (asserted by the e2e test). */
export const DEMO_EXPECTED = {
  detectors: [
    'A1-sql-injection',
    'A4-xss',
    'A5-hardcoded-secrets',
    'A6-weak-crypto',
    'A11-vulnerable-deps',
    'A12-security-misconfig',
  ],
  owaspCodes: ['A02', 'A03', 'A04', 'A05'],
} as const;

export function demoProjectFiles(): Record<string, string> {
  return {
    'README.md': [
      '# Acme Shop',
      '',
      'A deliberately vulnerable demo app for WebGuard. Do not deploy or run it.',
      '',
    ].join('\n'),

    'package.json': `${JSON.stringify(
      {
        name: 'acme-shop',
        version: '1.0.0',
        private: true,
        main: 'server.js',
        dependencies: {
          express: '^4.21.2',
          expresss: '^1.0.0',
          jsonwebtoken: '8.5.1',
          lodash: '4.17.4',
          mysql2: '^3.11.0',
          'serve-index': '^1.9.1',
        },
      },
      null,
      2,
    )}\n`,

    'config.js': [
      '// Application configuration',
      'module.exports = {',
      "  dbHost: 'localhost',",
      `  stripeSecretKey: '${DEMO_FAKE_STRIPE_KEY}',`,
      '};',
      '',
    ].join('\n'),

    'lib/passwords.js': [
      "const crypto = require('crypto');",
      '',
      '// Password hashing for user accounts',
      'function hashPassword(password) {',
      "  return crypto.createHash('md5').update(password).digest('hex');",
      '}',
      '',
      'module.exports = { hashPassword };',
      '',
    ].join('\n'),

    'server.js': [
      "const express = require('express');",
      "const mysql = require('mysql2');",
      "const serveIndex = require('serve-index');",
      "const config = require('./config');",
      "const { hashPassword } = require('./lib/passwords');",
      '',
      'const app = express();',
      'const db = mysql.createConnection({ host: config.dbHost });',
      'app.use(express.json());',
      '',
      '// Product search',
      "app.get('/api/products', (req, res) => {",
      '  db.query("SELECT * FROM products WHERE name LIKE \'%" + req.query.q + "%\'", (err, rows) => {',
      '    res.json(rows);',
      '  });',
      '});',
      '',
      '// Search results page',
      "app.get('/search', (req, res) => {",
      "  res.send('<h1>Results for ' + req.query.q + '</h1>');",
      '});',
      '',
      "app.post('/api/register', (req, res) => {",
      '  const hash = hashPassword(req.body.password);',
      "  db.query('INSERT INTO users (email, password) VALUES (?, ?)', [req.body.email, hash], () => {",
      '    res.sendStatus(201);',
      '  });',
      '});',
      '',
      '// Browse uploaded files',
      "app.use('/uploads', express.static('uploads'), serveIndex('uploads', { icons: true }));",
      '',
      'app.use((err, req, res, next) => {',
      '  res.status(500).send(err.stack);',
      '});',
      '',
      'app.listen(3000);',
      '',
    ].join('\n'),
  };
}

export function buildDemoZip(): Buffer {
  return buildZip(
    Object.entries(demoProjectFiles()).map(([name, data]) => ({ name, data, deflate: true })),
  );
}
