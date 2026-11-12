import type { ScanRollup } from '@webguard/core';
import { useState } from 'react';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import { SEVERITIES, SEVERITY_LABEL } from '../../lib/findings';
import { useChartTheme } from '../../lib/theme';
import { ChartTooltip } from './ChartTooltip';

/**
 * Part-to-whole of findings by severity (≤ 5 ordered segments). The HTML legend beside the
 * donut carries every label and count, so the tooltip only enhances; "Table" swaps the chart
 * for an equivalent table.
 */
export function SeverityDonut({ rollup }: { rollup: ScanRollup }) {
  const theme = useChartTheme();
  const [table, setTable] = useState(false);
  const data = SEVERITIES.map((s) => ({
    key: s,
    name: SEVERITY_LABEL[s],
    value: rollup.bySeverity[s] ?? 0,
  }));
  const total = rollup.total;
  const pct = (v: number) => (total ? `${Math.round((v / total) * 100)}%` : '0%');

  return (
    <section className="card chart-card" aria-labelledby="sev-title">
      <header className="chart-head">
        <h3 id="sev-title">Findings by severity</h3>
        <button
          type="button"
          className="btn btn-small btn-ghost"
          aria-pressed={table}
          onClick={() => setTable((t) => !t)}
        >
          {table ? 'Chart' : 'Table'}
        </button>
      </header>
      {table ? (
        <table className="data-table compact">
          <thead>
            <tr>
              <th scope="col">Severity</th>
              <th scope="col" className="num">
                Findings
              </th>
              <th scope="col" className="num">
                Share
              </th>
            </tr>
          </thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.key}>
                <th scope="row">{d.name}</th>
                <td className="num">{d.value}</td>
                <td className="num">{pct(d.value)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="donut-layout">
          <div className="donut" aria-hidden="true">
            {total > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={data.filter((d) => d.value > 0)}
                    dataKey="value"
                    nameKey="name"
                    innerRadius="62%"
                    outerRadius="100%"
                    startAngle={90}
                    endAngle={-270}
                    stroke={theme.surface}
                    strokeWidth={2}
                    isAnimationActive={false}
                  >
                    {data
                      .filter((d) => d.value > 0)
                      .map((d) => (
                        <Cell key={d.key} fill={theme.severity[d.key]} />
                      ))}
                  </Pie>
                  <Tooltip
                    content={
                      <ChartTooltip format={(v, name) => `${name}: ${v} (${pct(Number(v))})`} />
                    }
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="donut-empty" />
            )}
            <div className="donut-center">
              <span className="donut-total">{total}</span>
              <span className="muted">findings</span>
            </div>
          </div>
          <ul className="legend" aria-label="Findings by severity">
            {data.map((d) => (
              <li key={d.key}>
                <span className={`swatch sev-${d.key}`} aria-hidden="true" />
                <span className="legend-name">{d.name}</span>
                <span className="legend-value">{d.value}</span>
                <span className="legend-share muted">{pct(d.value)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
