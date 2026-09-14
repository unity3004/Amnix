import { useNavigate } from 'react-router-dom'
import { ChevronRight, User } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import { formatRelativeTime } from '@/lib/format'
import type { CaseRead } from '@/types/api'

const STATUS_TONE: Record<CaseRead['status'], 'accent' | 'neutral' | 'success' | 'warning'> = {
  OPEN: 'accent',
  INVESTIGATING: 'warning',
  RESOLVED: 'success',
  CLOSED: 'neutral',
}

/** REAL BACKEND DATA -- every field rendered here comes directly from
 * one CaseRead row (GET /cases). `severity` is the value CaseService
 * already derived (max severity among linked alerts, or null) --
 * rendered as-is, never recomputed here.
 */
export function CaseRow({ caseItem }: { caseItem: CaseRead }) {
  const navigate = useNavigate()

  return (
    <button
      type="button"
      onClick={() => navigate(`/cases/${caseItem.id}`)}
      className="flex w-full flex-col gap-2 border-b border-border-faint px-5 py-3 text-left transition-colors duration-fast last:border-b-0 hover:bg-surface-hover sm:flex-row sm:items-center sm:gap-4"
    >
      <div className="flex items-center gap-3 sm:contents">
        <span className="shrink-0 font-mono text-xs text-fg-subtle">#{caseItem.case_number}</span>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-fg">{caseItem.title}</p>
          <p className="truncate text-[11px] text-fg-subtle">{caseItem.description}</p>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 sm:shrink-0 sm:justify-end sm:gap-4">
        <Badge tone={STATUS_TONE[caseItem.status]}>{caseItem.status}</Badge>
        <Badge tone={caseItem.priority}>{caseItem.priority} priority</Badge>
        {caseItem.severity && <Badge tone={caseItem.severity} dot>{caseItem.severity}</Badge>}
        <span
          className="flex items-center gap-1 text-xs text-fg-subtle"
          title={caseItem.owner_id ? `Owned by user ${caseItem.owner_id}` : 'No owner assigned'}
        >
          <User className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
          {caseItem.owner_id ? 'Owned' : 'Unassigned'}
        </span>
        <span className="text-xs text-fg-subtle" title={new Date(caseItem.updated_at).toLocaleString()}>
          {formatRelativeTime(caseItem.updated_at)}
        </span>
        <ChevronRight className="hidden size-3.5 shrink-0 text-fg-subtle sm:block" strokeWidth={2} aria-hidden="true" />
      </div>
    </button>
  )
}
