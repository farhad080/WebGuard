import type { OwaspCategory, ScanRollup } from '@webguard/core';
import { useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { OWASP_CATEGORIES, splitOwasp } from '../../lib/findings';
import { useChartTheme } from '../../lib/theme';
import { ChartTooltip } from './ChartTooltip';

/**
 * Findings per OWASP Top 10:2025 category — one nominal series, so every bar is slot-1 blue
 * (no legend; the title names it). Horizontal bars, ranked, with the count at each bar end.
 */
export function OwaspBars({ rollup }: { rollup: ScanRollup }) {
  const theme = useChartTheme();
  const [table, setTable] = useState(false);
  const rows = OWASP_CATEGORIES.map((c: OwaspCategory) => ({
    category: c,
    ...splitOwasp(c),
    count: rollup.byOwaspCategory[c] ?? 0,
  }));
  const present = rows
    .filter((r) => r.count > 0)
    .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));
  const height = Math.max(present.length, 1) * 34 + 32;

  return (
    <section className="card chart-card" aria-labelledby="owasp-title">
      <header className="chart-head">
        <h3 id="owasp-title">Findings by OWASP Top 10:2025 category</h3>
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
              <th scope="col">Category</th>
              <th scope="col" className="num">
                Findings
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.code}>
                <th scope="row">
                  {r.code} {r.name}
                </th>
                <td className="num">{r.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : present.length === 0 ? (
        <p className="muted">No findings in any category.</p>
      ) : (
        <>
          <div style={{ height }} aria-hidden="true">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={present}
                layout="vertical"
                margin={{ top: 4, right: 36, bottom: 4, left: 0 }}
                barCategoryGap={8}
              >
                <CartesianGrid horizontal={false} stroke={theme.grid} />
                <XAxis
                  type="number"
                  allowDecimals={false}
                  tick={{ fill: theme.muted, fontSize: 12 }}
                  axisLine={{ stroke: theme.axis }}
                  tickLine={false}
                />
                <YAxis
                  type="category"
                  dataKey="code"
                  width={44}
                  tick={{ fill: theme.textSecondary, fontSize: 12, fontWeight: 600 }}
                  axisLine={{ stroke: theme.axis }}
                  tickLine={false}
                />
                <Tooltip
                  cursor={{ fill: theme.grid, opacity: 0.5 }}
                  content={
                    <ChartTooltip
                      format={(v, _n, row) => `${String(row.code)} ${String(row.name)}: ${v}`}
                    />
                  }
                />
                <Bar
                  dataKey="count"
                  name="Findings"
                  fill={theme.series1}
                  radius={[0, 4, 4, 0]}
                  maxBarSize={18}
                  isAnimationActive={false}
                >
                  <LabelList
                    dataKey="count"
                    position="right"
                    fill={theme.textSecondary}
                    fontSize={12}
                  />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <ul className="owasp-key">
            {present.map((r) => (
              <li key={r.code}>
                <strong>{r.code}</strong> {r.name} <span className="muted">· {r.count}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
