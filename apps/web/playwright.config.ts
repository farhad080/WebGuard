import { existsSync } from 'node:fs';
import { defineConfig } from '@playwright/test';

/**
 * E2E smoke against the real stack (API + worker + Vite dev server, Postgres + Redis from
 * docker compose). Uses the preinstalled Chromium/Chrome — Playwright browsers are never
 * downloaded. Set CHROMIUM_PATH to override the auto-detected executable.
 */
function findChromium(): string | undefined {
  const candidates = [
    process.env.CHROMIUM_PATH,
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files\\Chromium\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  ];
  return candidates.find((p): p is string => !!p && existsSync(p));
}

const executablePath = findChromium();
const WEB_URL = process.env.E2E_BASE_URL ?? 'http://localhost:5173';
// Own port so another local app on :3000 is never mistaken for the API. Both the API (PORT)
// and the Vite proxy (VITE_API_PROXY_TARGET) receive it.
const API_PORT = process.env.E2E_API_PORT ?? '3100';
const serverEnv = {
  PORT: API_PORT,
  VITE_API_PROXY_TARGET: `http://localhost:${API_PORT}`,
};

export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: WEB_URL,
    trace: 'retain-on-failure',
    launchOptions: {
      executablePath,
      args: ['--headless', '--no-sandbox'],
    },
  },
  // Started unless already running (reuseExistingServer), from the repo root.
  webServer: [
    {
      command: 'npm run dev --workspace apps/api',
      cwd: '../..',
      url: `http://localhost:${API_PORT}/api/health`,
      env: serverEnv,
      reuseExistingServer: true,
      timeout: 120_000,
    },
    {
      command: 'npm run worker --workspace apps/api',
      cwd: '../..',
      wait: { stdout: /waiting for scan jobs/ },
      env: serverEnv,
      reuseExistingServer: true,
      timeout: 120_000,
    },
    {
      command: 'npm run dev --workspace apps/web',
      cwd: '../..',
      url: WEB_URL,
      env: serverEnv,
      reuseExistingServer: true,
      timeout: 120_000,
    },
  ],
});
