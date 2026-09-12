import { SearchCode } from 'lucide-react'
import { EmptyState } from '@/components/ui/EmptyState'
import { SeverityBadge } from '@/components/ui/Badge'
import { cn } from '@/lib/cn'
import type { InvestigationStageGroup } from '../types'

const STAGE_ACCENT: Record<string, string> = {
  new: 'text-accent',
  investigating: 'text-medium',
  resolved: 'text-success',
}

/** DERIVED FROM REAL BACKEND DATA -- grouped purely from Alert.status
 * on the bounded GET /alerts page (see deriveInvestigationActivity.ts).
 * No per-alert /investigation request is made here.
 */
export function InvestigationActivityPanel({ groups }: { groups: InvestigationStageGroup[] }) {
  const total = groups.reduce((sum, g) => sum + g.alerts.length, 0)

  if (total === 0) {
    return (
      <EmptyState
        icon={SearchCode}
        title="No investigations yet"
        description="Investigation activity will appear here once alerts are generated."
      />
    )
  }

  return (
    <div className="grid grid-cols-3 divide-x divide-border-faint">
      {groups.map((group) => (
        <div key={group.stage} className="px-4 py-3">
          <div className="mb-2 flex items-center justify-between">
            <span className={cn('text-xs font-semibold uppercase tracking-wide', STAGE_ACCENT[group.stage])}>
              {group.label}
            </span>
            <span className="text-xs tabular-nums text-fg-subtle">{group.alerts.length}</span>
          </div>
          <ul className="flex flex-col gap-2">
            {group.alerts.slice(0, 3).map((alert) => (
              <li key={alert.id} className="flex items-center gap-1.5">
                <SeverityBadge severity={alert.severity} />
              </li>
            ))}
            {group.alerts.length === 0 && <li className="text-xs text-fg-subtle">None</li>}
          </ul>
        </div>
      ))}
    </div>
  )
}
