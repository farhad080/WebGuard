import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { config } from '../config.js';

/**
 * HTML → PDF with the *preinstalled* Chromium (never downloaded at runtime), run as
 * `--headless --no-sandbox --print-to-pdf`. The executable comes from CHROMIUM_PATH or the
 * usual install locations. Called from the worker, not the request thread.
 */

const CANDIDATES: Record<string, string[]> = {
  linux: [
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/snap/bin/chromium',
  ],
  darwin: [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
  ],
  win32: [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files\\Chromium\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  ],
};

export class PdfRenderError extends Error {
  override name = 'PdfRenderError';
}

/** The Chromium executable to use, or undefined if none is installed/configured. */
export function findChromium(): string | undefined {
  const configured = config.chromiumPath;
  if (configured) return existsSync(configured) ? configured : undefined;
  return (CANDIDATES[process.platform] ?? []).find((p) => existsSync(p));
}

export async function renderPdf(
  html: string,
  options: { timeoutMs?: number } = {},
): Promise<Buffer> {
  const executable = findChromium();
  if (!executable) {
    throw new PdfRenderError(
      `No Chromium found${config.chromiumPath ? ` at CHROMIUM_PATH=${config.chromiumPath}` : ''}; install Chromium/Chrome or set CHROMIUM_PATH`,
    );
  }
  const dir = await mkdtemp(path.join(os.tmpdir(), 'webguard-pdf-'));
  const htmlPath = path.join(dir, 'report.html');
  const pdfPath = path.join(dir, 'report.pdf');
  try {
    await writeFile(htmlPath, html, 'utf8');
    await new Promise<void>((resolve, reject) => {
      const child = spawn(
        executable,
        [
          '--headless',
          '--no-sandbox',
          '--disable-gpu',
          '--disable-dev-shm-usage',
          '--disable-extensions',
          '--disable-background-networking',
          '--no-first-run',
          '--no-default-browser-check',
          '--no-pdf-header-footer',
          `--user-data-dir=${path.join(dir, 'profile')}`,
          `--print-to-pdf=${pdfPath}`,
          pathToFileURL(htmlPath).href,
        ],
        { stdio: ['ignore', 'ignore', 'pipe'] },
      );
      let stderr = '';
      child.stderr.on('data', (d: Buffer) => {
        stderr = (stderr + d.toString()).slice(-2000);
      });
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new PdfRenderError(`Chromium timed out after ${options.timeoutMs ?? 60_000} ms`));
      }, options.timeoutMs ?? 60_000);
      child.on('error', (err) => {
        clearTimeout(timer);
        reject(new PdfRenderError(`Could not start Chromium: ${err.message}`));
      });
      child.on('exit', (code) => {
        clearTimeout(timer);
        if (code === 0 && existsSync(pdfPath)) resolve();
        else
          reject(
            new PdfRenderError(
              `Chromium exited with code ${code}: ${stderr.trim().split('\n').at(-1) ?? ''}`,
            ),
          );
      });
    });
    const pdf = await readFile(pdfPath);
    if (pdf.subarray(0, 4).toString('latin1') !== '%PDF')
      throw new PdfRenderError('Chromium did not produce a PDF');
    return pdf;
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}
