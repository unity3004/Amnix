import { motion } from 'motion/react'
import type { SeverityCount } from '../types'

const SEVERITY_COLOR: Record<SeverityCount['severity'], string> = {
  critical: 'var(--color-critical)',
  high: 'var(--color-high)',
  medium: 'var(--color-medium)',
  low: 'var(--color-low)',
}

export function SeverityDistribution({ data }: { data: SeverityCount[] }) {
  const total = data.reduce((sum, d) => sum + d.count, 0) || 1

  return (
    <div className="flex flex-col gap-3">
      {data.map((item) => {
        const percent = Math.round((item.count / total) * 100)
        return (
          <div key={item.severity}>
            <div className="mb-1 flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 font-medium capitalize text-fg-muted">
                <span
                  className="size-1.5 rounded-full"
                  style={{ backgroundColor: SEVERITY_COLOR[item.severity] }}
                  aria-hidden="true"
                />
                {item.severity}
              </span>
              <span className="tabular-nums text-fg-subtle">{item.count}</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-surface-elevated">
              <motion.div
                className="h-full rounded-full"
                style={{ backgroundColor: SEVERITY_COLOR[item.severity] }}
                initial={{ width: 0 }}
                animate={{ width: `${percent}%` }}
                transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}
