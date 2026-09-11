import { useNavigate } from 'react-router-dom'
import { SeverityBadge, Badge } from '@/components/ui/Badge'
import { formatRelativeTime } from '@/lib/format'
import { lookupMitreTechnique } from '@/features/dashboard/mitreRegistry'
import type { AlertRead } from '@/types/api'

const STATUS_TONE: Record<AlertRead['status'], 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

/** REAL BACKEND DATA -- every field rendered here comes directly from
 * one AlertRead row (GET /alerts). `mitre` is the one derived value
 * (static rule_id lookup).
 */
export function AlertRow({ alert }: { alert: AlertRead }) {
  const navigate = useNavigate()
  const mitre = lookupMitreTechnique(alert.rule_id)
  const eventCount = alert.source_event_ids.length

  return (
    <button
      type="button"
      onClick={() => navigate(`/alerts/${alert.id}`)}
      className="flex w-full flex-col gap-2 border-b border-border-faint px-5 py-3 text-left transition-colors duration-fast last:border-b-0 hover:bg-surface-hover sm:flex-row sm:items-center sm:gap-4"
    >
      <div className="flex items-center gap-3 sm:contents">
        <SeverityBadge severity={alert.severity} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-fg">{alert.title}</p>
          <p className="flex items-center gap-1.5 truncate font-mono text-[11px] text-fg-subtle">
            {alert.rule_id}
            {mitre && <span className="text-accent-strong">· {mitre.techniqueId}</span>}
          </p>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 sm:shrink-0 sm:justify-end sm:gap-4">
        <Badge tone={STATUS_TONE[alert.status]}>{alert.status}</Badge>
        <span className="text-xs text-fg-subtle sm:w-24 sm:text-right">First seen {formatRelativeTime(alert.first_seen)}</span>
        <span className="font-mono text-xs text-fg-subtle sm:w-20 sm:text-right">
          {eventCount} event{eventCount === 1 ? '' : 's'}
        </span>
      </div>
    </button>
  )
}
