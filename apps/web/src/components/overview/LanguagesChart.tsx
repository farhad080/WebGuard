import type { LanguageBreakdown } from '@webguard/core';
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
import { useChartTheme } from '../../lib/theme';
import { ChartTooltip } from '../charts/ChartTooltip';
import { languageName } from './format';

type Measure = 'lines' | 'files';

/**
 * Language mix: one nominal series (slot-1 blue, no legend — the title names it), ranked
 * horizontal bars with the value at each bar end. Toggle between lines of code and files;
 * the Table view lists both plus the analysis depth.
 */
export function LanguagesChart({ languages }: { languages: LanguageBreakdown[] }) {
  const theme = useChartTheme();
  const [measure, setMeasure] = useState<Measure>('lines');
  const [table, setTable] = useState(false);
  const rows = languages
    .map((l) => ({
      language: l.language,
      name: languageName(l.language),
      value: measure === 'lines' ? l.loc.total : l.files,
    }))
    .sort((a, b) => b.value - a.value || a.name.localeCompare(b.name));
  const height = Math.max(rows.length, 1) * 30 + 32;
  const unit = measure === 'lines' ? 'lines' : 'files';

  return (
    <section className="card chart-card" aria-labelledby="languages-title">
      <header className="chart-head">
        <h3 id="languages-title">Languages by {unit}</h3>
        <div className="chart-actions">
          <div className="segmented" role="group" aria-label="Measure">
            {(['lines', 'files'] as const).map((m) => (
              <button
                key={m}
                type="button"
                className="btn btn-small btn-ghost"
                aria-pressed={measure === m}
                onClick={() => setMeasure(m)}
              >
                {m === 'lines' ? 'Lines' : 'Files'}
              </button>
            ))}
          </div>
          <button
            type="button"
            className="btn btn-small btn-ghost"
            aria-pressed={table}
            onClick={() => setTable((t) => !t)}
          >
            {table ? 'Chart' : 'Table'}
          </button>
        </div>
      </header>
      {languages.length === 0 ? (
        <p className="muted">No source files in a recognized language.</p>
      ) : table ? (
        <table className="data-table compact" data-testid="languages-table">
          <thead>
            <tr>
              <th scope="col">Language</th>
              <th scope="col" className="num">
                Files
              </th>
              <th scope="col" className="num">
                Lines
              </th>
              <th scope="col">Analysis</th>
            </tr>
          </thead>
          <tbody>
            {languages.map((l) => (
              <tr key={l.language}>
                <th scope="row">{languageName(l.language)}</th>
                <td className="num">{l.files.toLocaleString()}</td>
                <td className="num">{l.loc.total.toLocaleString()}</td>
                <td>{l.analysisLabel}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div style={{ height }} aria-hidden="true">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={rows}
              layout="vertical"
              margin={{ top: 4, right: 52, bottom: 4, left: 0 }}
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
                dataKey="name"
                width={92}
                tick={{ fill: theme.textSecondary, fontSize: 12 }}
                axisLine={{ stroke: theme.axis }}
                tickLine={false}
              />
              <Tooltip
                cursor={{ fill: theme.grid, opacity: 0.5 }}
                content={
                  <ChartTooltip
                    format={(v, _n, row) =>
                      `${String(row.name)}: ${Number(v).toLocaleString()} ${unit}`
                    }
                  />
                }
              />
              <Bar
                dataKey="value"
                name={unit}
                fill={theme.series1}
                radius={[0, 4, 4, 0]}
                maxBarSize={18}
                isAnimationActive={false}
              >
                <LabelList
                  dataKey="value"
                  position="right"
                  fill={theme.textSecondary}
                  fontSize={12}
                  formatter={(v: number) => v.toLocaleString()}
                />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </section>
  );
}
