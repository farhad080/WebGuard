import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { finding } from '../test/utils';
import { FindingsTable } from './FindingsTable';

const findings = [
  finding({ id: 'low1', severity: 'low', confidence: 0.6, filePath: 'src/util.js' }),
  finding({ id: 'crit1', severity: 'critical', confidence: 0.95, filePath: 'src/db.js' }),
  finding({
    id: 'high1',
    severity: 'high',
    confidence: 0.4,
    owaspCategory: 'A01:2025-Broken Access Control',
    filePath: 'routes/admin.js',
    evidence: ['Candidate (missing authorization): DELETE /users/:id'],
  }),
  finding({
    id: 'med1',
    severity: 'medium',
    confidence: 0.85,
    owaspCategory: 'A02:2025-Security Misconfiguration',
    filePath: 'server.js',
  }),
];

function setup() {
  render(
    <MemoryRouter>
      <FindingsTable findings={findings} />
    </MemoryRouter>,
  );
  const table = () => screen.getByRole('table');
  const severities = () =>
    within(table())
      .getAllByRole('row')
      .slice(1)
      .map((r) => within(r).getAllByRole('cell')[0]!.textContent);
  return { table, severities };
}

describe('findings table filters', () => {
  it('sorts by severity by default and always shows severity + confidence', () => {
    const { table, severities } = setup();
    expect(severities()).toEqual(['Critical', 'High', 'Medium', 'Low']);
    expect(within(table()).getAllByText(/^\d+%$/)).toHaveLength(4);
  });

  it('labels candidate and low-confidence findings', () => {
    const { table } = setup();
    const row = within(table()).getByText('routes/admin.js:10').closest('tr')!;
    expect(within(row).getByText('Candidate')).toBeInTheDocument();
    expect(within(row).getByText(/low confidence/i)).toBeInTheDocument();
    expect(screen.getByTestId('findings-count')).toHaveTextContent('1 need manual review');
  });

  it('filters by severity, OWASP category, min confidence, and file', async () => {
    const ue = userEvent.setup();
    const { severities } = setup();

    await ue.click(screen.getByRole('checkbox', { name: 'Critical' }));
    await ue.click(screen.getByRole('checkbox', { name: 'High' }));
    expect(severities()).toEqual(['Critical', 'High']);

    await ue.selectOptions(screen.getByLabelText('Min confidence'), '0.5');
    expect(severities()).toEqual(['Critical']);

    await ue.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(severities()).toHaveLength(4);

    await ue.selectOptions(
      screen.getByLabelText('OWASP category'),
      'A02:2025-Security Misconfiguration',
    );
    expect(severities()).toEqual(['Medium']);

    await ue.click(screen.getByRole('button', { name: 'Clear filters' }));
    await ue.type(screen.getByLabelText('File'), 'src/');
    expect(severities()).toEqual(['Critical', 'Low']);
    expect(screen.getByTestId('findings-count')).toHaveTextContent('Showing 2 of 4 findings');

    await ue.clear(screen.getByLabelText('File'));
    await ue.type(screen.getByLabelText('File'), 'nothing-matches');
    expect(screen.getByText('No findings match these filters')).toBeInTheDocument();
  });

  it('can re-sort by confidence and back to severity', async () => {
    const ue = userEvent.setup();
    const { severities } = setup();
    await ue.click(screen.getByRole('button', { name: 'Confidence' }));
    expect(severities()).toEqual(['Critical', 'Medium', 'Low', 'High']);
    await ue.click(screen.getByRole('button', { name: 'Severity' }));
    expect(severities()).toEqual(['Critical', 'High', 'Medium', 'Low']);
  });
});
