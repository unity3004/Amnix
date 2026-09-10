import { motion } from 'motion/react'
import { ShieldAlert } from 'lucide-react'
import { SeverityBadge, Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { formatRelativeTime } from '@/lib/format'
import type { RecentAlertSummary } from '../types'

const STATUS_TONE: Record<RecentAlertSummary['status'], 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

export function RecentAlertsPanel({ alerts, onSelect }: { alerts: RecentAlertSummary[]; onSelect?: (id: string) => void }) {
  if (alerts.length === 0) {
    return <EmptyState icon={ShieldAlert} title="No active alerts" description="AMNIX has not raised any alerts recently." />
  }

  return (
    <ul className="divide-y divide-border-faint">
      {alerts.map((alert, index) => (
        <motion.li
          key={alert.id}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: index * 0.035, ease: [0.16, 1, 0.3, 1] }}
        >
          <button
            type="button"
            onClick={() => onSelect?.(alert.id)}
            className="flex w-full items-center gap-4 px-5 py-3 text-left transition-colors duration-fast hover:bg-surface-hover"
          >
            <SeverityBadge severity={alert.severity} />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium text-fg">{alert.title}</p>
              <p className="truncate font-mono text-[11px] text-fg-subtle">{alert.ruleId}</p>
            </div>
            <Badge tone={STATUS_TONE[alert.status]}>{alert.status}</Badge>
            <span className="w-20 shrink-0 text-right text-xs text-fg-subtle">
              {formatRelativeTime(alert.occurredAt)}
            </span>
          </button>
        </motion.li>
      ))}
    </ul>
  )
}
