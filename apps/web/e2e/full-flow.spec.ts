import { readFile } from 'node:fs/promises';
import { expect, test, type Page } from '@playwright/test';
import { buildDemoZip, DEMO_EXPECTED } from '../../api/demo/vulnerable-shop';

/**
 * Full product flow against the real stack (API + worker + web, Postgres + Redis), using the
 * seeded "Acme Shop" demo project: register → sign out → sign in → create project → upload →
 * poll to completion → expected categories → finding detail (Monaco) → PDF report → rescan →
 * compare. Cleans up by deleting the project.
 */
const demoZip = buildDemoZip();

async function uploadAndWait(page: Page) {
  await page
    .getByLabel(/drop a project zip/i)
    .setInputFiles({ name: 'acme-shop.zip', mimeType: 'application/zip', buffer: demoZip });
  // The live view polls queued → running → completed.
  await expect(page.getByRole('list', { name: 'Scan progress' })).toBeVisible();
  await expect(page.getByTestId('dashboard')).toBeVisible({ timeout: 90_000 });
}

test('register → login → upload demo → findings → finding → PDF → rescan → compare', async ({
  page,
}) => {
  const email = `e2e-${Date.now()}@example.test`;
  const password = 'e2e-password-123';

  // Register (signs in), then sign out and sign in again.
  await page.goto('/register');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByLabel('Confirm password').fill(password);
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();

  await page.getByRole('link', { name: 'Account' }).click();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();

  // Create a project and scan the demo ZIP.
  await page.getByLabel('New project').fill('E2E Acme Shop');
  await page.getByRole('button', { name: 'Create project' }).click();
  await page.getByRole('link', { name: 'E2E Acme Shop' }).click();
  await uploadAndWait(page);
  const firstScanUrl = page.url();

  // Expected OWASP categories and detector hits.
  await expect(page.getByLabel(/^Risk grade [A-F]$/)).toBeVisible();
  const owaspKey = page.locator('.owasp-key');
  for (const code of DEMO_EXPECTED.owaspCodes) await expect(owaspKey).toContainText(code);
  const table = page.locator('.findings-table');
  for (const location of [
    'server.js:13', // SQL injection
    'server.js:20', // reflected XSS
    'config.js:4', // hardcoded secret
    'lib/passwords.js:5', // weak password hashing
    'package.json:8', // typosquat
    'package.json:10', // vulnerable lodash
    'server.js:34', // stack-trace disclosure
  ]) {
    await expect(table.getByRole('row').filter({ hasText: location }).first()).toBeVisible();
  }
  await expect(page.getByRole('heading', { name: /Informational/ })).toBeVisible();

  // Open the SQL injection finding.
  await table.getByRole('row').filter({ hasText: 'server.js:13' }).getByRole('link').click();
  await expect(page.getByTestId('finding-badges')).toContainText('Critical');
  await expect(page.getByTestId('finding-badges')).toContainText('CWE-89');
  await expect(page.locator('.monaco-editor .vuln-line').first()).toBeAttached({ timeout: 30_000 });
  await page.getByRole('tab', { name: 'Fix' }).click();
  await expect(page.getByText('After (secure)')).toBeVisible();

  // The secret finding's code view is redacted.
  await page.goto(firstScanUrl);
  await table.getByRole('row').filter({ hasText: 'config.js:4' }).getByRole('link').click();
  await expect(page.locator('.monaco-editor')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('.monaco-editor')).toContainText('[redacted');
  await expect(page.locator('.monaco-editor')).not.toContainText('N0tR3al');

  // Download the PDF report.
  await page.goto(firstScanUrl);
  const downloadPromise = page.waitForEvent('download', { timeout: 90_000 });
  await page.getByRole('button', { name: 'Download PDF' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^webguard-report-.+\.pdf$/);
  const pdf = await readFile((await download.path())!);
  expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');

  // Rescan the same code and compare: nothing new, nothing fixed, everything still open.
  await page.getByRole('link', { name: 'Project', exact: true }).click();
  await uploadAndWait(page);
  await page.getByRole('link', { name: 'See what changed →' }).click();
  const result = page.getByTestId('compare-result');
  await expect(result).toBeVisible();
  await expect(page.getByRole('tab', { name: 'New (0)' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Fixed (0)' })).toBeVisible();
  await expect(page.getByRole('tab', { name: /^Still open \([1-9]\d*\)$/ })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Risk score over time' })).toBeVisible();

  // Clean up: delete the project (rows cascade; stored files are removed too).
  await page.goto('/projects');
  await page.getByRole('button', { name: 'Delete E2E Acme Shop' }).click();
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByText('No projects yet')).toBeVisible();
});
