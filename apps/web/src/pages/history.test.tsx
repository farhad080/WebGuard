import type { ScanComparison } from '@webguard/core';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { finding, mockApi, renderApp, rollup, scan, user } from '../test/utils';

const s1 = scan({
  id: 's1',
  status: 'completed',
  createdAt: '2026-11-01T10:00:00.000Z',
  summary: { rollup: rollup({ total: 6, riskScore: 80, grade: 'F' }) },
});
const s2 = scan({
  id: 's2',
  status: 'completed',
  createdAt: '2026-11-05T10:00:00.000Z',
  summary: { rollup: rollup({ total: 4, riskScore: 62, grade: 'D' }) },
});
const s3 = scan({
  id: 's3',
  status: 'completed',
  createdAt: '2026-11-10T10:00:00.000Z',
  summary: { rollup: rollup({ total: 2, riskScore: 30, grade: 'B' }) },
});

function comparison(scanId: string, againstId: string): ScanComparison {
  const ref = (id: string) => {
    const s = [s1, s2, s3].find((x) => x.id === id)!;
    return { id, createdAt: s.createdAt, finishedAt: null, rollup: s.summary!.rollup! };
  };
  const open = finding({ id: 'open1', filePath: 'src/db.js', lineStart: 12 });
  return {
    scan: ref(scanId),
    against: ref(againstId),
    fixed: [
      finding({ id: 'fx1', severity: 'critical', filePath: 'src/login.js' }),
      finding({ id: 'fx2', severity: 'high', filePath: 'src/search.js' }),
    ],
    new: [finding({ id: 'nw1', severity: 'medium', filePath: 'src/crypto.js' })],
    persisting: [{ finding: open, previous: { ...open, id: 'open0', lineStart: 9 } }],
    summary: { fixed: 2, new: 1, persisting: 1, totalDelta: -1, riskScoreDelta: -32 },
  };
}

describe('history & compare', () => {
  it('compares the latest two completed scans by default and shows the diff', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/projects/:id': () => ({
        body: { id: 'p1', userId: 'u1', name: 'Shop', createdAt: '2026-10-01T00:00:00.000Z' },
      }),
      'GET /api/projects/:id/scans': () => ({
        body: [s3, scan({ id: 'q', status: 'running' }), s2, s1],
      }),
      'GET /api/scans/:id/compare': (req, p) => ({
        body: comparison(p.id!, req.query.get('against')!),
      }),
    });
    renderApp('/projects/p1/history');

    const result = await screen.findByTestId('compare-result', {}, { timeout: 8000 });
    expect(calls.find((c) => c.path.endsWith('/compare'))?.path).toBe('/api/scans/s3/compare');
    expect(calls.find((c) => c.path.endsWith('/compare'))?.query.get('against')).toBe('s2');

    expect(within(result).getByText('Fixed').parentElement).toHaveTextContent('Fixed2');
    expect(within(result).getByText('New').parentElement).toHaveTextContent('New1');
    expect(within(result).getByText('Still open').parentElement).toHaveTextContent('62 → 30 (-32)');

    const ue = userEvent.setup();
    // "New" tab first.
    expect(screen.getByRole('tabpanel')).toHaveTextContent('src/crypto.js');
    await ue.click(screen.getByRole('tab', { name: 'Fixed (2)' }));
    expect(screen.getByRole('tabpanel')).toHaveTextContent('src/login.js');
    expect(screen.getByRole('tabpanel')).toHaveTextContent('src/search.js');
    await ue.click(screen.getByRole('tab', { name: 'Still open (1)' }));
    expect(screen.getByRole('tabpanel')).toHaveTextContent('src/db.js:12 (was line 9)');

    // Pick another baseline, then swap.
    await ue.selectOptions(screen.getByLabelText('Baseline'), 's1');
    await screen.findByTestId('compare-result');
    expect(
      calls
        .filter((c) => c.path.endsWith('/compare'))
        .at(-1)
        ?.query.get('against'),
    ).toBe('s1');
    await ue.click(screen.getByRole('button', { name: 'Swap' }));
    await screen.findByTestId('compare-result');
    const last = calls.filter((c) => c.path.endsWith('/compare')).at(-1)!;
    expect(last.path).toBe('/api/scans/s1/compare');
    expect(last.query.get('against')).toBe('s3');

    // Risk trend has a table view with every completed scan, oldest first.
    await ue.click(screen.getByRole('button', { name: 'Table' }));
    const rows = within(screen.getByTestId('trend-table')).getAllByRole('row').slice(1);
    expect(rows.map((r) => within(r).getByLabelText(/Risk grade/).textContent)).toEqual([
      'F',
      'D',
      'B',
    ]);
  });

  it('explains that two scans are needed', async () => {
    mockApi({
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/projects/:id': () => ({
        body: { id: 'p1', userId: 'u1', name: 'Shop', createdAt: '2026-10-01T00:00:00.000Z' },
      }),
      'GET /api/projects/:id/scans': () => ({ body: [s1] }),
    });
    renderApp('/projects/p1/history');
    expect(await screen.findByText(/at least two scans/)).toBeInTheDocument();
  });
});
