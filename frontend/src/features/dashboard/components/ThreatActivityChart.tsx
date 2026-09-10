import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { ThreatActivityPoint } from '../types'

const SERIES: { key: keyof Omit<ThreatActivityPoint, 'timestamp'>; label: string; color: string }[] = [
  { key: 'critical', label: 'Critical', color: 'var(--color-critical)' },
  { key: 'high', label: 'High', color: 'var(--color-high)' },
  { key: 'medium', label: 'Medium', color: 'var(--color-medium)' },
  { key: 'low', label: 'Low', color: 'var(--color-low)' },
]

function CustomTooltip({ active, payload, label }: { active?: boolean; payload?: { value: number; dataKey: string }[]; label?: string }) {
  if (!active || !payload?.length) return null
  const time = label ? new Date(label).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : ''
  return (
    <div className="rounded-md border border-border-strong bg-surface-elevated px-3 py-2 text-xs shadow-elevated">
      <p className="mb-1.5 font-medium text-fg">{time}</p>
      {SERIES.map((series) => {
        const point = payload.find((p) => p.dataKey === series.key)
        if (!point) return null
        return (
          <div key={series.key} className="flex items-center justify-between gap-4 py-0.5">
            <span className="flex items-center gap-1.5 text-fg-muted">
              <span className="size-1.5 rounded-full" style={{ backgroundColor: series.color }} />
              {series.label}
            </span>
            <span className="font-medium tabular-nums text-fg">{point.value}</span>
          </div>
        )
      })}
    </div>
  )
}

/** Recharts' automatic "nice ticks" algorithm, combined with
 * allowDecimals={false}, can round two distinct computed tick values
 * down to the same integer on a small (single-digit) stacked range --
 * producing a visibly non-monotonic axis (e.g. "1, 3, 5, 3, 2" top to
 * bottom), found during Step 12A's own browser verification
 * screenshot review. Computing a small, explicit, always-ascending
 * integer tick set here sidesteps that algorithm entirely rather than
 * trying to tune it.
 */
function computeYAxisTicks(data: ThreatActivityPoint[]): number[] {
  const max = data.reduce((acc, point) => Math.max(acc, point.critical + point.high + point.medium + point.low), 0)
  const ceiling = Math.max(4, Math.ceil(max / 2) * 2)
  const step = Math.max(1, Math.ceil(ceiling / 4))
  const ticks: number[] = []
  for (let value = 0; value <= ceiling; value += step) ticks.push(value)
  return ticks
}

export function ThreatActivityChart({ data }: { data: ThreatActivityPoint[] }) {
  const yTicks = computeYAxisTicks(data)
  return (
    <div className="h-64 w-full" role="img" aria-label="Alert activity over the last 24 hours, by severity">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <defs>
            {SERIES.map((series) => (
              <linearGradient key={series.key} id={`fill-${series.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={series.color} stopOpacity={0.35} />
                <stop offset="100%" stopColor={series.color} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid stroke="var(--color-border-faint)" vertical={false} />
          <XAxis
            dataKey="timestamp"
            tickFormatter={(value: string) => new Date(value).toLocaleTimeString(undefined, { hour: 'numeric' })}
            tick={{ fill: 'var(--color-fg-subtle)', fontSize: 11 }}
            axisLine={{ stroke: 'var(--color-border)' }}
            tickLine={false}
            minTickGap={32}
          />
          <YAxis
            tick={{ fill: 'var(--color-fg-subtle)', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            width={28}
            allowDecimals={false}
            domain={[0, yTicks[yTicks.length - 1]]}
            ticks={yTicks}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ stroke: 'var(--color-border-strong)', strokeWidth: 1 }} />
          {SERIES.map((series) => (
            <Area
              key={series.key}
              type="monotone"
              dataKey={series.key}
              stackId="severity"
              stroke={series.color}
              strokeWidth={1.5}
              fill={`url(#fill-${series.key})`}
              isAnimationActive
              animationDuration={700}
              animationEasing="ease-out"
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
