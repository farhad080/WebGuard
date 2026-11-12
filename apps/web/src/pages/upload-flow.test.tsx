import type { Scan } from '@webguard/core';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { finding, installFakeXhr, mockApi, renderApp, rollup, scan, user } from '../test/utils';
import { scanPolling } from './ScanPage';

describe('upload → poll → dashboard', () => {
  beforeEach(() => {
    scanPolling.intervalMs = 20;
  });
  afterEach(() => {
    scanPolling.intervalMs = 2000;
  });

  it('uploads a ZIP with progress, polls the scan until completed, then shows the dashboard', async () => {
    const previous = scan({
      id: 's0',
      status: 'completed',
      createdAt: '2026-11-11T10:00:00.000Z',
      startedAt: '2026-11-11T10:00:01.000Z',
      finishedAt: '2026-11-11T10:00:05.000Z',
      summary: { rollup: rollup({ total: 6, riskScore: 70, grade: 'F' }) },
    });
    const statuses: Scan['status'][] = ['queued', 'running', 'running', 'completed'];
    let polls = 0;
    const { calls } = mockApi({
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/projects/:id': () => ({
        body: { id: 'p1', userId: 'u1', name: 'Shop', createdAt: '2026-11-10T00:00:00.000Z' },
      }),
      'GET /api/projects/:id/scans': () => ({ body: [previous] }),
      'GET /api/scans/:id': () => {
        const status = statuses[Math.min(polls, statuses.length - 1)]!;
        polls += 1;
        return {
          body: scan({
            id: 's1',
            status,
            createdAt: '2026-11-12T10:00:00.000Z',
            startedAt: status === 'queued' ? null : '2026-11-12T10:00:01.000Z',
            finishedAt: status === 'completed' ? '2026-11-12T10:00:04.000Z' : null,
            summary:
              status === 'completed'
                ? {
                    rollup: rollup(),
                    informationalNotes: [
                      {
                        id: 'captcha',
                        title: 'CAPTCHA bypass',
                        references: ['#15'],
                        note: 'Runtime behavior; test dynamically.',
                      },
                    ],
                  }
                : null,
          }),
        };
      },
      'GET /api/scans/:id/findings': () => ({
        body: [finding({ severity: 'critical' }), finding({ severity: 'high', confidence: 0.3 })],
      }),
    });
    const xhr = installFakeXhr(() => ({ status: 201, body: scan({ id: 's1' }) }));

    renderApp('/projects/p1');
    expect(await screen.findByRole('heading', { name: 'Shop' })).toBeInTheDocument();

    const file = new File(['PK\u0003\u0004'], 'site.zip', { type: 'application/zip' });
    const input = screen.getByLabelText(/drop a project zip/i);
    await userEvent.upload(input, file);

    // Upload progress is visible while the bytes are in flight.
    expect(await screen.findByRole('progressbar', { name: 'Upload progress' })).toBeInTheDocument();
    expect(xhr.sent[0]!.url).toBe('/api/projects/p1/scans');
    expect(xhr.sent[0]!.headers.Authorization).toMatch(/^Bearer /);
    expect((xhr.sent[0]!.body as FormData).get('file')).toBeInstanceOf(File);

    // Navigates to the live scan view, which polls without blocking.
    expect(await screen.findByTestId('scan-live')).toBeInTheDocument();

    // ...until the scan completes and the dashboard renders.
    const dashboard = await screen.findByTestId('dashboard', {}, { timeout: 3000 });
    expect(polls).toBeGreaterThanOrEqual(4);
    expect(screen.queryByTestId('scan-live')).not.toBeInTheDocument();
    expect(within(dashboard).getByTestId('total-findings')).toHaveTextContent('4');
    expect(within(dashboard).getByLabelText('Risk grade D')).toBeInTheDocument();

    // Trend against the previous completed scan of the project.
    const trend = within(dashboard).getByTestId('trend-tile');
    expect(trend).toHaveTextContent('6 → 4');
    expect(trend).toHaveTextContent('2 fewer findings');

    // Severity legend (HTML, not only the chart) and the OWASP chart.
    const legend = within(dashboard).getByRole('list', { name: 'Findings by severity' });
    expect(within(legend).getByText('Critical').parentElement).toHaveTextContent('Critical125%');
    expect(
      within(dashboard).getByRole('heading', { name: /OWASP Top 10:2025/ }),
    ).toBeInTheDocument();

    // Findings table and the separate informational section.
    expect(await screen.findByTestId('findings-count')).toHaveTextContent(
      'Showing 2 of 2 findings',
    );
    expect(screen.getByText(/1 need manual review/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Informational/ })).toBeInTheDocument();
    expect(screen.getByText('CAPTCHA bypass')).toBeInTheDocument();

    // No more polling once completed.
    const after = polls;
    await new Promise((r) => setTimeout(r, 100));
    expect(polls).toBe(after);
    expect(calls.filter((c) => c.path === '/api/scans/s1/findings')).toHaveLength(1);
  });

  it('shows the failure reason for a failed scan', async () => {
    mockApi({
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/scans/:id': () => ({
        body: scan({ status: 'failed', summary: { error: 'ZIP contains no files' } }),
      }),
    });
    renderApp('/scans/s1');
    expect(await screen.findByText('The scan failed')).toBeInTheDocument();
    expect(screen.getByText('ZIP contains no files')).toBeInTheDocument();
  });

  it('rejects a non-ZIP file before uploading', async () => {
    mockApi({
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/projects/:id': () => ({
        body: { id: 'p1', userId: 'u1', name: 'Shop', createdAt: '2026-11-10T00:00:00.000Z' },
      }),
      'GET /api/projects/:id/scans': () => ({ body: [] }),
    });
    const xhr = installFakeXhr(() => ({ status: 201, body: {} }));
    renderApp('/projects/p1');
    const input = await screen.findByLabelText(/drop a project zip/i);
    await userEvent.upload(input, new File(['x'], 'notes.txt', { type: 'text/plain' }), {
      applyAccept: false,
    });
    expect(await screen.findByRole('alert')).toHaveTextContent('"notes.txt" is not a .zip file.');
    expect(xhr.sent).toHaveLength(0);
  });
  it('shows how many dependency/build files were ignored during extraction', async () => {
    mockApi({
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/scans/:id': () => ({
        body: scan({
          status: 'completed',
          startedAt: '2026-11-12T10:00:01.000Z',
          finishedAt: '2026-11-12T10:00:04.000Z',
          summary: {
            rollup: rollup(),
            filesParsed: 3,
            extractedFiles: 3,
            skippedFileCount: 89654,
            skippedDirs: ['.git', 'node_modules'],
            profile: {
              languages: [{ language: 'javascript', files: 3, bytes: 300 }],
              frameworks: [],
              manifests: [],
              sensitivePaths: [],
              sourceFiles: [],
              ignored: {
                total: 0,
                byReason: { 'ignored-dir': 0, binary: 0, 'too-large': 0, unrecognized: 0 },
              },
              totals: { files: 3, bytes: 300 },
            },
          },
        }),
      }),
      'GET /api/projects/:id/scans': () => ({ body: [] }),
      'GET /api/scans/:id/findings': () => ({ body: [] }),
    });
    renderApp('/scans/s1');
    const line = await screen.findByTestId('skipped-files');
    expect(line).toHaveTextContent(
      `${(89654).toLocaleString()} dependency/build files in .git, node_modules (not extracted or scanned)`,
    );
  });

  describe('client-side size check (server MAX_UPLOAD_MB via GET /api/limits)', () => {
    const MiB = 1024 * 1024;
    const zipOf = (bytes: number) => {
      const file = new File(['PK'], 'project.zip', { type: 'application/zip' });
      Object.defineProperty(file, 'size', { value: bytes });
      return file;
    };
    const routes = () => ({
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/projects/:id': () => ({
        body: { id: 'p1', userId: 'u1', name: 'Shop', createdAt: '2026-11-10T00:00:00.000Z' },
      }),
      'GET /api/projects/:id/scans': () => ({ body: [] }),
      'GET /api/limits': () => ({ body: { maxUploadMb: 512, maxUploadBytes: 512 * MiB } }),
    });

    it('shows the server limit and sends a ~300 MB ZIP (over the old 50 MB cap)', async () => {
      mockApi(routes());
      const xhr = installFakeXhr(() => ({ status: 201, body: scan({ id: 's9' }) }));
      renderApp('/projects/p1');
      expect(await screen.findByText(/Max 512 MB\./)).toBeInTheDocument();
      const input = screen.getByLabelText(/drop a project zip/i);
      await userEvent.upload(input, zipOf(300 * MiB));
      await screen.findByText('Uploading…');
      expect(xhr.sent).toHaveLength(1);
    });

    it('rejects a ZIP over the server limit before uploading, stating the limit', async () => {
      mockApi(routes());
      const xhr = installFakeXhr(() => ({ status: 201, body: {} }));
      renderApp('/projects/p1');
      await screen.findByText(/Max 512 MB\./);
      await userEvent.upload(screen.getByLabelText(/drop a project zip/i), zipOf(600 * MiB));
      expect(await screen.findByRole('alert')).toHaveTextContent(
        '"project.zip" is 600 MB; the upload limit is 512 MB.',
      );
      expect(xhr.sent).toHaveLength(0);
    });
  });
});
