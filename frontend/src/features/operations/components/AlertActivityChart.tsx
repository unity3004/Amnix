import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useReducedMotion } from 'motion/react'
import type { ActivityBucket } from '../deriveOperationsSummary'

const SERIES: { key: 'critical' | 'high' | 'medium' | 'low'; label: string; color: string }[] = [
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
        if (!point || point.value === 0) return null
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

/** Same explicit, always-ascending integer Y-axis tick strategy
 * established in features/dashboard/components/ThreatActivityChart.tsx
 * -- Recharts' automatic "nice ticks" algorithm can round two distinct
 * computed values down to the same integer on a small range, producing
 * a visibly non-monotonic axis. Reused here rather than re-derived.
 */
function computeYAxisTicks(buckets: ActivityBucket[]): number[] {
  const max = buckets.reduce((acc, b) => Math.max(acc, b.total), 0)
  const ceiling = Math.max(4, Math.ceil(max / 2) * 2)
  const step = Math.max(1, Math.ceil(ceiling / 4))
  const ticks: number[] = []
  for (let value = 0; value <= ceiling; value += step) ticks.push(value)
  return ticks
}

/** DERIVED ANALYST VIEW -- a visualization of the real, bounded alert
 * dataset this page already fetched (see deriveActivityTimeline), never
 * a historical trend and never a growth-percentage claim. Empty
 * buckets are rendered as zero, not omitted -- an honest reflection of
 * "no alert in this bounded result fell into this slot," not proof
 * that nothing happened globally during that time.
 */
export function AlertActivityChart({ buckets }: { buckets: ActivityBucket[] }) {
  const prefersReducedMotion = useReducedMotion()
  const data = buckets.map((b) => ({ timestamp: b.bucketStart, ...b.counts }))
  const yTicks = computeYAxisTicks(buckets)
  return (
    <div className="h-56 w-full" role="img" aria-label="Recent alert activity observed in the selected window, by severity">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <defs>
            {SERIES.map((series) => (
              <linearGradient key={series.key} id={`ops-fill-${series.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={series.color} stopOpacity={0.35} />
                <stop offset="100%" stopColor={series.color} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid stroke="var(--color-border-faint)" vertical={false} />
          <XAxis
            dataKey="timestamp"
            tickFormatter={(value: string) => new Date(value).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })}
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
              fill={`url(#ops-fill-${series.key})`}
              isAnimationActive={!prefersReducedMotion}
              animationDuration={500}
              animationEasing="ease-out"
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
