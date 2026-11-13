import type { ProjectStats, StatsTreeNode } from '@webguard/core';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { CodeViewProps } from '../components/code/MonacoCodeView';
import { finding, mockApi, renderApp, rollup, scan, user } from '../test/utils';

// Monaco needs a real browser: a stand-in that shows which file and lines it was given.
vi.mock('../components/code/MonacoCodeView', () => ({
  default: (p: CodeViewProps) => (
    <pre data-testid="code" data-line-start={p.lineStart ?? ''}>
      {p.code}
    </pre>
  ),
}));

const file = (
  path: string,
  findings = 0,
  worstSeverity: StatsTreeNode['worstSeverity'] = null,
): StatsTreeNode => ({
  name: path.split('/').pop()!,
  path,
  type: 'file',
  files: 1,
  findings,
  worstSeverity,
  language: 'javascript',
});

const tree: StatsTreeNode = {
  name: '',
  path: '',
  type: 'dir',
  files: 4,
  findings: 3,
  worstSeverity: 'critical',
  children: [
    {
      name: 'src',
      path: 'src',
      type: 'dir',
      files: 2,
      findings: 2,
      worstSeverity: 'critical',
      children: [file('src/db.js', 2, 'critical'), file('src/util.js')],
    },
    {
      name: 'docs',
      path: 'docs',
      type: 'dir',
      files: 1,
      findings: 0,
      worstSeverity: null,
      children: [],
      omitted: { dirs: 0, files: 1 },
    },
    file('package.json', 1, 'high'),
  ],
};

const stats: ProjectStats = {
  version: 1,
  status: 'complete',
  stage: 'complete',
  computedAt: '2026-11-13T10:00:03.000Z',
  size: {
    files: 4,
    folders: 2,
    zipBytes: 2048,
    unpackedBytes: 6144,
    loc: { code: 120, comment: 20, blank: 10, total: 150 },
    largestFiles: [{ path: 'src/db.js', bytes: 4000, lines: 100, language: 'javascript' }],
    longestFiles: [{ path: 'src/db.js', bytes: 4000, lines: 100, language: 'javascript' }],
  },
  languages: [
    {
      language: 'javascript',
      files: 2,
      bytes: 5000,
      loc: { code: 110, comment: 20, blank: 10, total: 140 },
      analysisDepth: 'full-ast',
      analysisLabel: 'full AST analysis',
    },
    {
      language: 'python',
      files: 1,
      bytes: 100,
      loc: { code: 10, comment: 0, blank: 0, total: 10 },
      analysisDepth: 'pattern-only',
      analysisLabel: 'secrets/crypto/deps/config only',
    },
  ],
  stack: {
    frameworks: [{ name: 'Express', kind: 'framework', evidence: 'package.json' }],
    entryPoints: ['server.js'],
    packageManagers: [{ name: 'npm', lockfile: 'package-lock.json' }],
  },
  tree,
  dependencies: {
    direct: 5,
    transitive: 57,
    total: 62,
    vulnerable: 2,
    outdated: 1,
    typosquats: [{ name: 'expresss', target: 'express' }],
    manifests: ['package-lock.json', 'package.json'],
  },
  security: {
    total: 3,
    bySeverity: { critical: 1, high: 2, medium: 0, low: 0, info: 0 },
    byOwaspCategory: { 'A05:2025-Injection': 2, 'A03:2025-Software Supply Chain Failures': 1 },
    topFiles: [{ path: 'src/db.js', findings: 2, worstSeverity: 'critical' }],
    riskScore: 62,
    grade: 'D',
    gradeReason: 'capped at D',
  },
  skipped: {
    ignoredDirFiles: 1500,
    ignoredDirs: ['node_modules'],
    binary: 3,
    tooLarge: 1,
    unrecognized: 2,
    unsupportedEntries: 0,
  },
  scan: {
    startedAt: '2026-11-13T10:00:00.000Z',
    finishedAt: '2026-11-13T10:00:02.500Z',
    durationMs: 2500,
    rules: ['A1-sql-injection', 'A4-xss', 'A11-vulnerable-deps'],
    filesParsed: 2,
    parseErrors: 0,
  },
};

const findings = [
  finding({ id: 'f-a', severity: 'high', filePath: 'src/db.js', lineStart: 20, lineEnd: 20 }),
  finding({ id: 'f-b', severity: 'critical', filePath: 'src/db.js', lineStart: 7, lineEnd: 9 }),
];

function setup(overrides: { stats?: ProjectStats | null; status?: 'completed' | 'failed' } = {}) {
  const status = overrides.status ?? 'completed';
  return mockApi({
    'GET /api/auth/me': () => ({ body: user }),
    'GET /api/scans/:id': () => ({
      body: scan({
        status,
        finishedAt: '2026-11-13T10:00:02.500Z',
        summary: status === 'completed' ? { rollup: rollup() } : { error: 'Archive is corrupt' },
      }),
    }),
    'GET /api/projects/:id/scans': () => ({ body: [] }),
    'GET /api/scans/:id/findings': () => ({ body: findings }),
    'GET /api/scans/:id/stats': () => ({
      body: {
        scanId: 's1',
        status,
        stats: overrides.stats === undefined ? stats : overrides.stats,
        error: status === 'failed' ? 'Archive is corrupt' : null,
      },
    }),
    'GET /api/scans/:id/file': (req) => ({
      body: {
        path: req.query.get('path'),
        language: 'javascript',
        size: 40,
        lineCount: 2,
        content: 'const a = 1;\nconst b = 2;\n',
        truncated: false,
        binary: false,
        maxBytes: 2097152,
      },
    }),
  });
}

describe('Project Overview tab', () => {
  it('renders the tiles, charts, panels and scan info from the stored stats', async () => {
    const api = setup();
    const ue = userEvent.setup();
    renderApp('/scans/s1');

    // The dashboard is the default tab; the overview is one click away.
    // First render of the dashboard (Recharts) can be slow on a cold run.
    const tablist = await screen.findByRole('tablist', { name: 'Scan views' }, { timeout: 5000 });
    expect(api.calls.some((c) => c.path.endsWith('/stats'))).toBe(false);
    await ue.click(within(tablist).getByRole('tab', { name: 'Project overview' }));
    await screen.findByTestId('project-overview');

    const tiles = screen.getByTestId('overview-tiles');
    expect(within(tiles).getByTestId('tile-files')).toHaveTextContent('4');
    expect(within(tiles).getByTestId('tile-files')).toHaveTextContent('1,506 not analyzed');
    expect(within(tiles).getByTestId('tile-folders')).toHaveTextContent('2');
    expect(within(tiles).getByTestId('tile-loc')).toHaveTextContent('150');
    expect(within(tiles).getByTestId('tile-size')).toHaveTextContent('6 KB');
    expect(within(tiles).getByTestId('tile-size')).toHaveTextContent('2 KB ZIP');
    expect(within(tiles).getByTestId('tile-deps')).toHaveTextContent('62');
    expect(within(tiles).getByTestId('tile-deps')).toHaveTextContent('5 direct · 57 transitive');
    expect(within(tiles).getByTestId('tile-grade')).toHaveTextContent('D');
    expect(within(tiles).getByTestId('tile-grade')).toHaveTextContent('62/100');

    // Languages chart, with a table view that lists both measures and the analysis depth.
    expect(screen.getByRole('heading', { name: 'Languages by lines' })).toBeInTheDocument();
    await ue.click(screen.getByRole('button', { name: 'Files' }));
    expect(screen.getByRole('heading', { name: 'Languages by files' })).toBeInTheDocument();
    const langCard = screen
      .getByRole('heading', { name: 'Languages by files' })
      .closest('section')!;
    await ue.click(within(langCard).getByRole('button', { name: 'Table' }));
    const langTable = screen.getByTestId('languages-table');
    expect(within(langTable).getAllByRole('row')).toHaveLength(3);
    expect(langTable).toHaveTextContent('Python');
    expect(langTable).toHaveTextContent('secrets/crypto/deps/config only');

    // LOC split and the honest per-language analysis depth.
    const loc = screen.getByTestId('loc-breakdown');
    expect(loc).toHaveTextContent('Code120 (80%)');
    expect(loc).toHaveTextContent('Comment20 (13.3%)');
    expect(loc).toHaveTextContent('Blank10 (6.7%)');
    const depth = screen.getByTestId('analysis-depth');
    expect(depth).toHaveTextContent('JavaScriptfull AST analysis');
    expect(depth).toHaveTextContent('Pythonsecrets/crypto/deps/config only');

    // Dependencies and security panels; skipped files are shown, not hidden.
    const deps = screen.getByTestId('deps-panel');
    expect(deps).toHaveTextContent('Vulnerable2');
    expect(deps).toHaveTextContent('End-of-life / outdated1');
    expect(deps).toHaveTextContent('expresss — did you mean express?');
    const sec = screen.getByTestId('security-panel');
    expect(within(sec).getByTestId('severity-breakdown')).toHaveTextContent('Critical1');
    expect(within(sec).getByTestId('severity-breakdown')).toHaveTextContent('High2');
    expect(sec).toHaveTextContent('A05 Injection · 2');
    expect(within(sec).getByTestId('top-files')).toHaveTextContent('src/db.js 2 · worst critical');
    const skipped = screen.getByTestId('skipped-summary');
    expect(skipped).toHaveTextContent('In ignored folders1,500 (node_modules)');
    expect(skipped).toHaveTextContent('Binary files3');
    expect(skipped).toHaveTextContent('Over the size limit1');

    const info = screen.getByTestId('scan-info');
    expect(info).toHaveTextContent('2.5 s');
    expect(info).toHaveTextContent('3 rules');

    // Stack.
    expect(screen.getByText('Express')).toBeInTheDocument();
    expect(screen.getByText('npm (package-lock.json)')).toBeInTheDocument();
  });

  it('shows the folder tree colored by severity; clicking a file opens the viewer', async () => {
    const api = setup();
    const ue = userEvent.setup();
    renderApp('/scans/s1?tab=overview');
    await screen.findByTestId('project-overview');

    const tree = screen.getByRole('list', { name: 'Project files' });
    const src = within(tree).getByRole('button', { name: /^src\// });
    expect(src).toHaveAttribute('aria-expanded', 'false');
    expect(src).toHaveTextContent('2 files');
    expect(src).toHaveTextContent('2 findings, worst Critical');
    expect(src.querySelector('.swatch.sev-critical')).not.toBeNull();
    const docs = within(tree).getByRole('button', { name: /^docs\// });
    expect(docs.querySelector('.tree-sev-none')).not.toBeNull();

    await ue.click(docs);
    expect(tree).toHaveTextContent('+1 file not listed');

    await ue.click(src);
    expect(src).toHaveAttribute('aria-expanded', 'true');
    await ue.click(within(tree).getByRole('button', { name: 'Open src/db.js, 2 findings' }));

    const dialog = await screen.findByRole('dialog', { name: 'src/db.js' });
    await within(dialog).findByTestId('code');
    expect(api.calls.find((c) => c.path === '/api/scans/s1/file')!.query.get('path')).toBe(
      'src/db.js',
    );
    // Focused on the file's most severe finding; both of its findings are listed.
    expect(within(dialog).getByTestId('code')).toHaveAttribute('data-line-start', '7');
    expect(within(dialog).getByTestId('viewer-summary')).toHaveTextContent('lines 7–9');
    expect(
      within(dialog).getByRole('navigation', { name: 'Findings in src/db.js' }),
    ).toHaveTextContent('2 findings in this file');

    // A file without findings opens without a highlight.
    await ue.click(within(dialog).getByRole('button', { name: 'Close file viewer' }));
    await ue.click(within(tree).getByRole('button', { name: 'Open src/util.js' }));
    const plain = await screen.findByRole('dialog', { name: 'src/util.js' });
    expect(within(plain).getByTestId('viewer-summary')).toHaveTextContent(
      'No findings in this file.',
    );
    expect(await within(plain).findByTestId('code')).toHaveAttribute('data-line-start', '');
  });

  it('shows partial stats under a failed scan', async () => {
    setup({
      status: 'failed',
      stats: {
        ...stats,
        status: 'partial',
        stage: 'extraction',
        languages: [],
        stack: null,
        tree: null,
        dependencies: null,
        security: null,
        size: { ...stats.size, folders: null, loc: null, largestFiles: [], longestFiles: [] },
      },
    });
    renderApp('/scans/s1');
    expect(await screen.findByRole('alert')).toHaveTextContent('Archive is corrupt');
    const note = await screen.findByTestId('partial-stats');
    expect(note).toHaveTextContent('Partial statistics');
    expect(note).toHaveTextContent('after extraction, during analysis');
    expect(screen.getByTestId('tile-files')).toHaveTextContent('4');
    expect(screen.getByTestId('tile-grade')).toHaveTextContent('—');
    expect(screen.getByTestId('security-panel')).toHaveTextContent('did not finish its analysis');
    expect(screen.getByTestId('skipped-summary')).toHaveTextContent('1,500');
    expect(screen.queryByRole('tablist', { name: 'Scan views' })).not.toBeInTheDocument();
  });

  it('explains a scan without statistics', async () => {
    setup({ stats: null });
    renderApp('/scans/s1?tab=overview');
    expect(await screen.findByText('No statistics for this scan')).toBeInTheDocument();
    expect(screen.getByText(/predates the Project Overview/)).toBeInTheDocument();
  });
});
