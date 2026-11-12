import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { finding, mockApi, renderApp, user } from '../test/utils';

// Monaco needs a real browser; the code view is covered by the e2e smoke instead.
vi.mock('../components/code/CodeView', () => ({
  CodeView: (p: { path: string; lineStart: number; lineEnd: number }) => (
    <div data-testid="code-view">
      {p.path}:{p.lineStart}-{p.lineEnd}
    </div>
  ),
}));

const withRemediation = finding({
  id: 'f-sqli',
  severity: 'critical',
  confidence: 0.92,
  remediation: {
    templateId: 'A1-sql-injection',
    title: 'SQL injection in db.query',
    why: 'An attacker controls part of the SQL text.',
    impact: 'Read or modify any row in the database.',
    steps: ['Use placeholders for every value.', 'Validate the id as an integer.'],
    secureExample: {
      language: 'javascript',
      before: 'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
      after: 'db.query("SELECT * FROM users WHERE id = ?", [req.params.id])',
      contextualized: true,
      note: 'Verify the column list.',
    },
    references: [
      { title: 'OWASP SQL Injection Prevention', url: 'https://cheatsheetseries.owasp.org/' },
    ],
    generatedBy: 'template+context',
  },
});

describe('finding detail', () => {
  it('shows badges, the code view, and Explanation / Exploit / Fix tabs', async () => {
    mockApi({
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/findings/:id': () => ({ body: withRemediation }),
    });
    renderApp('/findings/f-sqli');
    expect(
      await screen.findByRole('heading', { name: 'SQL injection in db.query' }),
    ).toBeInTheDocument();

    const badges = screen.getByTestId('finding-badges');
    expect(within(badges).getByText('Critical')).toBeInTheDocument();
    expect(within(badges).getByText('92%')).toBeInTheDocument();
    expect(within(badges).getByText('A05')).toBeInTheDocument();
    expect(within(badges).getByRole('link', { name: 'CWE-89' })).toHaveAttribute(
      'href',
      'https://cwe.mitre.org/data/definitions/89.html',
    );
    expect(screen.getByTestId('code-view')).toHaveTextContent('src/db.js:10-10');

    const ue = userEvent.setup();
    const tabs = screen.getByRole('tablist', { name: 'Finding details' });
    expect(within(tabs).getByRole('tab', { name: 'Explanation' })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    expect(screen.getByRole('tabpanel')).toHaveTextContent(
      'User input is concatenated into a SQL query.',
    );
    expect(screen.getByRole('tabpanel')).toHaveTextContent('req.params.id flows into db.query');

    await ue.click(within(tabs).getByRole('tab', { name: 'Exploit / Impact' }));
    expect(screen.getByRole('tabpanel')).toHaveTextContent(
      'Read or modify any row in the database.',
    );

    // Keyboard navigation between tabs.
    await ue.keyboard('{ArrowRight}');
    const fixTab = within(tabs).getByRole('tab', { name: 'Fix' });
    expect(fixTab).toHaveAttribute('aria-selected', 'true');
    expect(fixTab).toHaveFocus();

    const panel = screen.getByRole('tabpanel');
    const steps = within(panel).getAllByRole('listitem').slice(0, 2);
    expect(steps.map((s) => s.textContent)).toEqual([
      'Use placeholders for every value.',
      'Validate the id as an integer.',
    ]);
    expect(within(panel).getByText('Before (vulnerable)')).toBeInTheDocument();
    expect(within(panel).getByText('After (secure)')).toBeInTheDocument();
    expect(within(panel).getByText('rewritten from your code')).toBeInTheDocument();

    await ue.click(within(panel).getByRole('button', { name: /Copy secure code/ }));
    // user-event installs its own clipboard stub; read back what was written.
    expect(await navigator.clipboard.readText()).toBe(
      withRemediation.remediation!.secureExample.after,
    );
    expect(await within(panel).findByText('Copied ✓')).toBeInTheDocument();
  });

  it('flags candidate findings for manual confirmation', async () => {
    mockApi({
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/findings/:id': () => ({
        body: finding({
          id: 'f-ac',
          severity: 'high',
          confidence: 0.45,
          owaspCategory: 'A01:2025-Broken Access Control',
          evidence: ['Candidate (missing authorization): DELETE /api/users/:id'],
          explanation: 'State-changing route without an authorization check.',
        }),
      }),
    });
    renderApp('/findings/f-ac');
    expect(await screen.findByText('Candidate')).toBeInTheDocument();
    expect(screen.getByRole('note')).toHaveTextContent(/Confirm it manually/);
    // Without a stored remediation, the Fix tab falls back to the fix suggestion.
    await userEvent.click(screen.getByRole('tab', { name: 'Fix' }));
    expect(screen.getByRole('tabpanel')).toHaveTextContent('Use parameterized queries.');
  });

  it('shows an error state for an unknown finding', async () => {
    mockApi({
      'GET /api/auth/me': () => ({ body: user }),
      'GET /api/findings/:id': () => ({ status: 404, body: { error: 'Not found' } }),
    });
    renderApp('/findings/nope');
    expect(await screen.findByRole('alert')).toHaveTextContent('Finding unavailable');
  });
});
