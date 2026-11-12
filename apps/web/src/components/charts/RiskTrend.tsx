import type { Scan } from '@webguard/core';
import { useState } from 'react';
import {
  CartesianGrid,
  LabelList,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { formatDateTime } from '../../lib/findings';
import { useChartTheme } from '../../lib/theme';
import { GradeBadge } from '../Badges';
import { ChartTooltip } from './ChartTooltip';

/**
 * Risk over time: one series (risk score 0–100, higher = worse) in slot-1 blue, so no legend.
 * Only the latest point is direct-labeled with its grade; the tooltip and the table view carry
 * every value.
 */
export function RiskTrend({ scans }: { scans: Scan[] }) {
  const theme = useChartTheme();
  const [table, setTable] = useState(false);
  const completed = scans
    .filter((s) => s.status === 'completed' && s.summary?.rollup)
    .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());
  // Several scans on one day would share a "Nov 12" tick; add the time when days repeat.
  const days = completed.map((s) => new Date(s.createdAt).toDateString());
  const withTime = new Set(days).size < days.length;
  const points = completed.map((s, i, all) => ({
    id: s.id,
    label: new Date(s.createdAt).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      ...(withTime ? { hour: 'numeric', minute: '2-digit' } : {}),
    }),
    when: formatDateTime(s.createdAt),
    score: s.summary!.rollup!.riskScore,
    grade: s.summary!.rollup!.grade,
    total: s.summary!.rollup!.total,
    last: i === all.length - 1 ? s.summary!.rollup!.grade : undefined,
  }));

  return (
    <section className="card chart-card" aria-labelledby="trend-title">
      <header className="chart-head">
        <h3 id="trend-title">Risk score over time</h3>
        {/* With fewer than two points there is no line to draw: the table is the only view. */}
        {points.length > 1 && (
          <button
            type="button"
            className="btn btn-small btn-ghost"
            aria-pressed={table}
            onClick={() => setTable((t) => !t)}
          >
            {table ? 'Chart' : 'Table'}
          </button>
        )}
      </header>
      {points.length === 0 ? (
        <p className="muted">No completed scans yet.</p>
      ) : table || points.length === 1 ? (
        <table className="data-table compact" data-testid="trend-table">
          <thead>
            <tr>
              <th scope="col">Scan</th>
              <th scope="col">Grade</th>
              <th scope="col" className="num">
                Risk score
              </th>
              <th scope="col" className="num">
                Findings
              </th>
            </tr>
          </thead>
          <tbody>
            {points.map((p) => (
              <tr key={p.id}>
                <th scope="row">{p.when}</th>
                <td>
                  <GradeBadge grade={p.grade} />
                </td>
                <td className="num">{p.score}</td>
                <td className="num">{p.total}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <>
          <div style={{ height: 220 }} aria-hidden="true">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={points} margin={{ top: 20, right: 28, bottom: 4, left: 0 }}>
                <CartesianGrid vertical={false} stroke={theme.grid} />
                <XAxis
                  dataKey="label"
                  tick={{ fill: theme.muted, fontSize: 12 }}
                  axisLine={{ stroke: theme.axis }}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 100]}
                  ticks={[0, 25, 50, 75, 100]}
                  width={36}
                  tick={{ fill: theme.muted, fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  cursor={{ stroke: theme.axis }}
                  content={
                    <ChartTooltip
                      format={(v, _n, row) =>
                        `${String(row.when)}: grade ${String(row.grade)}, risk ${v}, ${String(row.total)} findings`
                      }
                    />
                  }
                />
                <Line
                  type="linear"
                  dataKey="score"
                  name="Risk score"
                  stroke={theme.series1}
                  strokeWidth={2}
                  dot={{ r: 4, fill: theme.series1, stroke: theme.surface, strokeWidth: 2 }}
                  activeDot={{ r: 6, stroke: theme.surface, strokeWidth: 2 }}
                  isAnimationActive={false}
                >
                  <LabelList
                    dataKey="last"
                    position="top"
                    fill={theme.textPrimary}
                    fontSize={12}
                    fontWeight={700}
                  />
                </Line>
              </LineChart>
            </ResponsiveContainer>
          </div>
          <p className="muted small">
            Higher is worse. Latest: grade {points.at(-1)!.grade}, risk {points.at(-1)!.score}/100
            across {points.length} completed scans.
          </p>
        </>
      )}
    </section>
  );
}
