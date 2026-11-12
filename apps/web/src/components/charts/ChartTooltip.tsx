interface Payload {
  name?: string | number;
  value?: string | number | (string | number)[];
  payload?: Record<string, unknown>;
}

/** Shared Recharts tooltip body; styled by tokens so it reads in light and dark. */
export function ChartTooltip({
  active,
  payload,
  format,
}: {
  active?: boolean;
  payload?: Payload[];
  format: (value: string | number, name: string, row: Record<string, unknown>) => string;
}) {
  const item = payload?.[0];
  if (!active || !item) return null;
  const value = Array.isArray(item.value) ? item.value[0]! : (item.value ?? '');
  return (
    <div className="chart-tooltip">
      {format(value, String(item.name ?? ''), item.payload ?? {})}
    </div>
  );
}
