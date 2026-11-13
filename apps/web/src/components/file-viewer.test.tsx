import type { Finding, ScanFile } from '@webguard/core';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { Providers, createQueryClient } from '../App';
import { finding, mockApi, type MockResult } from '../test/utils';
import type { CodeViewProps } from './code/MonacoCodeView';
import { FindingsTable } from './FindingsTable';

// Monaco needs a real browser. This stand-in renders one <li> per line and applies the same
// highlight/mark logic (lineRoles) the viewer gives Monaco, so the overlay can be asserted.
vi.mock('./code/MonacoCodeView', async () => {
  const { lineRoles } = await import('./code/scan-file');
  return {
    default: (p: CodeViewProps) => {
      const lines = p.code.split('\n');
      if (lines[lines.length - 1] === '') lines.pop();
      const roles = lineRoles(p, p.marks ?? [], lines.length);
      return (
        <ol data-testid="code" aria-label={p.ariaLabel}>
          {lines.map((text, i) => (
            <li key={i} data-line={i + 1} data-role={roles.get(i + 1)}>
              {text}
            </li>
          ))}
        </ol>
      );
    },
  };
});

const serverJs = Array.from({ length: 40 }, (_, i) => `line ${i + 1};`).join('\n') + '\n';

const sqli = finding({
  id: 'f-sqli',
  severity: 'critical',
  filePath: 'server.js',
  lineStart: 13,
  lineEnd: 15,
  explanation: 'SQL injection in the login query. More text.',
});
const xss = finding({
  id: 'f-xss',
  severity: 'high',
  filePath: 'server.js',
  lineStart: 30,
  lineEnd: 30,
  detectorId: 'A4-xss',
  explanation: 'Reflected XSS in the search page. More.',
});
const dep = finding({
  id: 'f-dep',
  severity: 'medium',
  filePath: 'node_modules/lodash/index.js',
  lineStart: 9,
  lineEnd: 9,
  explanation: 'Vulnerable dependency.',
});
const findings: Finding[] = [sqli, xss, dep];

function file(overrides: Partial<ScanFile> = {}): ScanFile {
  return {
    path: 'server.js',
    language: 'javascript',
    size: serverJs.length,
    lineCount: 40,
    content: serverJs,
    truncated: false,
    binary: false,
    maxBytes: 2048 * 1024,
    ...overrides,
  };
}

function setup(fileRoute: (path: string) => MockResult) {
  const api = mockApi({
    'GET /api/scans/:id/file': (req) => fileRoute(req.query.get('path') ?? ''),
  });
  const client = createQueryClient();
  client.setDefaultOptions({ queries: { retry: false } });
  render(
    <Providers client={client}>
      <MemoryRouter>
        <FindingsTable findings={findings} />
      </MemoryRouter>
    </Providers>,
  );
  return { api, ue: userEvent.setup() };
}

const roleOf = (line: number) =>
  screen.getByTestId('code').querySelector(`[data-line="${line}"]`)!.getAttribute('data-role');

describe('findings file viewer', () => {
  it('makes every location an accessible button', () => {
    setup(() => ({ body: file() }));
    const table = screen.getByRole('table');
    for (const f of findings) {
      const btn = within(table).getByRole('button', {
        name: `Open ${f.filePath} at line ${f.lineStart}`,
      });
      expect(btn).toHaveAttribute('aria-haspopup', 'dialog');
    }
    expect(
      within(table).getByRole('button', { name: 'Open server.js at line 13' }),
    ).toHaveTextContent('server.js:13–15');
  });

  it('opens the full file highlighted at the finding, with other findings in the file marked', async () => {
    const { api, ue } = setup(() => ({ body: file() }));
    await ue.click(screen.getByRole('button', { name: 'Open server.js at line 13' }));

    const dialog = screen.getByRole('dialog', { name: 'server.js' });
    expect(within(dialog).getByRole('button', { name: 'Close file viewer' })).toHaveFocus();
    await within(dialog).findByTestId('code');

    const fileCalls = api.calls.filter((c) => c.path === '/api/scans/s1/file');
    expect(fileCalls).toHaveLength(1);
    expect(fileCalls[0]!.query.get('path')).toBe('server.js');

    expect(within(dialog).getByTestId('file-meta')).toHaveTextContent('JavaScript');
    expect(within(dialog).getByTestId('file-meta')).toHaveTextContent('40 lines');
    expect(within(dialog).getByTestId('viewer-summary')).toHaveTextContent(
      'SQL injection in the login query',
    );
    expect(within(dialog).getByTestId('viewer-summary')).toHaveTextContent('lines 13–15');

    // Full file, flagged lines highlighted, the file's other finding marked, the rest plain.
    expect(within(dialog).getAllByRole('listitem').length).toBeGreaterThanOrEqual(40);
    for (const l of [13, 14, 15]) expect(roleOf(l)).toBe('active');
    expect(roleOf(30)).toBe('other');
    for (const l of [1, 12, 16, 29, 31, 40]) expect(roleOf(l)).toBeNull();
    expect(screen.getByTestId('code')).toHaveAttribute(
      'aria-label',
      expect.stringContaining('1 other finding marked'),
    );

    // Side list: only this file's findings, the opened one current.
    const list = within(dialog).getByRole('navigation', { name: 'Findings in server.js' });
    expect(list).toHaveTextContent('2 findings in this file');
    expect(within(list).getAllByRole('button')).toHaveLength(2);
    expect(within(list).getByRole('button', { current: true })).toHaveTextContent('L13–15');

    // Picking the other finding moves the highlight; the file is not fetched again.
    await ue.click(within(list).getByRole('button', { name: /L30/ }));
    expect(roleOf(30)).toBe('active');
    for (const l of [13, 14, 15]) expect(roleOf(l)).toBe('other');
    expect(api.calls.filter((c) => c.path === '/api/scans/s1/file')).toHaveLength(1);
  });

  it('opens from the keyboard and closes with Escape, returning focus', async () => {
    const { ue } = setup(() => ({ body: file() }));
    const btn = screen.getByRole('button', { name: 'Open server.js at line 13' });
    btn.focus();
    await ue.keyboard('{Enter}');
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    await ue.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.getByRole('button', { name: 'Open server.js at line 13' })).toHaveFocus();
  });

  it('explains a file from an ignored dependency directory', async () => {
    const { ue } = setup(() => ({
      status: 404,
      body: {
        error: 'This file was not scanned.',
        reason: 'ignored_dir',
        ignoredDir: 'node_modules',
      },
    }));
    await ue.click(
      screen.getByRole('button', { name: 'Open node_modules/lodash/index.js at line 9' }),
    );
    const dialog = screen.getByRole('dialog');
    const status = await within(dialog).findByText('This file wasn’t scanned');
    expect(status.closest('[data-reason]')).toHaveTextContent(
      /ignored dependency\/build directory \(node_modules\/\)/,
    );
    expect(within(dialog).queryByTestId('code')).not.toBeInTheDocument();
  });

  it('explains a scan whose extracted files were removed', async () => {
    const { ue } = setup(() => ({
      status: 404,
      body: { error: 'gone', reason: 'extracted_unavailable' },
    }));
    await ue.click(screen.getByRole('button', { name: 'Open server.js at line 13' }));
    expect(await screen.findByText('Source no longer available')).toBeInTheDocument();
  });

  it('shows a truncated file with a notice, and a binary file without content', async () => {
    const head = serverJs.split('\n').slice(0, 20).join('\n') + '\n';
    let response = file({ content: head, lineCount: 20, truncated: true, maxBytes: 1024 });
    const { ue } = setup(() => ({ body: response }));

    await ue.click(screen.getByRole('button', { name: 'Open server.js at line 30' }));
    let dialog = screen.getByRole('dialog');
    const note = await within(dialog).findByRole('note');
    expect(note).toHaveTextContent('showing the first 20 lines');
    expect(note).toHaveTextContent('The flagged lines are beyond the part shown.');
    expect(roleOf(13)).toBe('other');

    await ue.click(within(dialog).getByRole('button', { name: 'Close file viewer' }));
    response = file({ path: 'node_modules/lodash/index.js', binary: true, content: '' });
    await ue.click(
      screen.getByRole('button', { name: 'Open node_modules/lodash/index.js at line 9' }),
    );
    dialog = screen.getByRole('dialog');
    expect(await within(dialog).findByText('Binary file')).toBeInTheDocument();
    expect(within(dialog).queryByTestId('code')).not.toBeInTheDocument();
  });
});
