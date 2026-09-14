import { Badge } from '@/components/ui/Badge'
import { LiveIndicator } from '@/components/live/LiveIndicator'
import { RefreshButton } from '@/components/live/RefreshButton'
import type { CaseRead, CaseStatus } from '@/types/api'
import type { LiveQueryState } from '@/lib/liveRefresh'

const STATUS_TONE: Record<CaseStatus, 'accent' | 'neutral' | 'success' | 'warning'> = {
  OPEN: 'accent',
  INVESTIGATING: 'warning',
  RESOLVED: 'success',
  CLOSED: 'neutral',
}

/** Sticky Incident Summary header -- every field is REAL GET /cases/{id}
 * data verbatim, no fabricated incident intelligence. LIVE indicator and
 * "last refreshed" reuse the exact same LiveIndicator/RefreshButton
 * components/liveRefresh.ts convention every other AMNIX live page uses
 * -- one polling source (15s), no duplicate timers.
 */
export function IncidentHeader({
  caseItem,
  liveState,
  lastSuccessfulRefreshAt,
  isRefreshing,
  onRefresh,
}: {
  caseItem: CaseRead
  liveState: LiveQueryState
  lastSuccessfulRefreshAt: Date | null
  isRefreshing: boolean
  onRefresh: () => void
}) {
  return (
    <header className="sticky top-0 z-10 border-b border-border bg-bg/95 px-6 py-4 backdrop-blur">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="font-mono text-xs text-fg-subtle">Case #{caseItem.case_number}</p>
          <h1 className="mt-1 truncate text-lg font-semibold text-fg">{caseItem.title}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Badge tone={STATUS_TONE[caseItem.status]}>{caseItem.status}</Badge>
            <Badge tone={caseItem.priority}>{caseItem.priority} priority</Badge>
            {caseItem.severity && <Badge tone={caseItem.severity} dot>{caseItem.severity}</Badge>}
            <span className="font-mono text-[11px] text-fg-subtle" title={caseItem.owner_id ?? undefined}>
              Owner: {caseItem.owner_id ?? 'Unassigned'}
            </span>
          </div>
        </div>

        <div className="flex shrink-0 flex-col items-end gap-2">
          <div className="flex items-center gap-3">
            <LiveIndicator state={liveState} lastSuccessfulRefreshAt={lastSuccessfulRefreshAt} />
            <RefreshButton onRefresh={onRefresh} isRefreshing={isRefreshing} />
          </div>
          <div className="flex gap-4 text-[11px] text-fg-subtle">
            <span title={new Date(caseItem.created_at).toLocaleString()}>Created {new Date(caseItem.created_at).toLocaleDateString()}</span>
            <span title={new Date(caseItem.updated_at).toLocaleString()}>Updated {new Date(caseItem.updated_at).toLocaleDateString()}</span>
          </div>
        </div>
      </div>
    </header>
  )
}
