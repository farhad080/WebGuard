import { expect, test } from '@playwright/test';
import { buildZip } from '../../api/test/zip-writer';

// A tiny Express app with one obvious SQL injection.
const vulnerableApp = buildZip([
  {
    name: 'package.json',
    data: JSON.stringify({
      name: 'e2e-shop',
      dependencies: { express: '^4.21.0', mysql2: '^3.11.0' },
    }),
  },
  {
    name: 'server.js',
    data: [
      "const express = require('express');",
      "const mysql = require('mysql2');",
      'const app = express();',
      "const db = mysql.createConnection({ host: 'localhost' });",
      '',
      "app.get('/users/:id', (req, res) => {",
      "  db.query('SELECT * FROM users WHERE id = ' + req.params.id, (err, rows) => {",
      '    res.json(rows);',
      '  });',
      '});',
      '',
      'app.listen(3000);',
      '',
    ].join('\n'),
  },
]);

test('register → create project → upload ZIP → dashboard → findings → finding detail', async ({
  page,
}) => {
  const email = `e2e-${Date.now()}@example.test`;
  const password = 'e2e-password-123';

  await page.goto('/projects');
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();

  await page.getByRole('link', { name: 'Create an account' }).click();
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByLabel('Confirm password').fill(password);
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();

  await page.getByLabel('New project').fill('E2E shop');
  await page.getByRole('button', { name: 'Create project' }).click();
  await page.getByRole('link', { name: 'E2E shop' }).click();
  await expect(page.getByRole('heading', { name: 'E2E shop' })).toBeVisible();

  await page
    .getByLabel(/drop a project zip/i)
    .setInputFiles({ name: 'shop.zip', mimeType: 'application/zip', buffer: vulnerableApp });

  // Live view polls until the worker completes the scan.
  await expect(page.getByTestId('dashboard')).toBeVisible({ timeout: 90_000 });
  await expect(page.getByTestId('total-findings')).not.toHaveText('0');
  await expect(page.getByLabel(/^Risk grade [A-F]$/)).toBeVisible();

  const sqli = page.getByRole('row').filter({ hasText: 'server.js:7' }).first();
  await expect(sqli).toBeVisible();
  await expect(sqli).toContainText('A05');
  await sqli.getByRole('link').click();

  // Finding detail: Monaco renders the real file with the vulnerable line highlighted.
  await expect(page.getByTestId('finding-badges')).toContainText('A05');
  await expect(page.locator('.monaco-editor')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('.monaco-editor .vuln-line').first()).toBeAttached();
  await page.getByRole('tab', { name: 'Fix' }).click();
  await expect(page.getByText('After (secure)')).toBeVisible();

  // Clean up: delete the project (cascades to its scans and findings).
  await page.goto('/projects');
  await page.getByRole('button', { name: 'Delete E2E shop' }).click();
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByText('No projects yet')).toBeVisible();
});
