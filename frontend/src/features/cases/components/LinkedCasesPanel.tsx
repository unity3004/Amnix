import { Link } from 'react-router-dom'
import { FolderKanban } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { Skeleton } from '@/components/ui/Skeleton'
import { useAlertCases } from '@/features/alerts/useAlertCases'
import type { CaseRead, CaseStatus } from '@/types/api'

const STATUS_TONE: Record<CaseStatus, 'accent' | 'neutral' | 'success' | 'warning'> = {
  OPEN: 'accent',
  INVESTIGATING: 'warning',
  RESOLVED: 'success',
  CLOSED: 'neutral',
}

const PAGE_SIZE = 50

/** GET /alerts/{id}/cases (Step 12V) -- the AUTHORITATIVE Alert -> Case
 * relationship, distinct from the Step 12U navigation-context breadcrumb
 * ("Back to Case #N") that may also be showing elsewhere on this page.
 * That breadcrumb only ever means "you clicked through from this case";
 * this panel is the real, backend-confirmed membership -- it renders
 * independently and never reads or references the breadcrumb's case ID.
 *
 * An alert can belong to zero, one, or multiple cases; this panel never
 * assumes exactly one. The heading count is the number of Cases THIS
 * bounded response actually returned, not a global total (GET
 * /alerts/{id}/cases, like every other list endpoint in AMNIX, has no
 * COUNT(*) query) -- if the page came back full, the count is qualified
 * as "current page" rather than presented as if it were complete.
 */
export function LinkedCasesPanel({ alertId }: { alertId: string }) {
  const { data, isPending, isError, refetch } = useAlertCases(alertId)
  const cases = data?.items ?? []
  const pageMayBeIncomplete = cases.length === PAGE_SIZE

  return (
    <div>
      <div className="flex items-center justify-between px-5 pt-4 pb-2">
        <div>
          <h3 className="text-sm font-semibold tracking-wide text-fg">
            Linked Cases{!isPending && !isError && cases.length > 0 ? ` (${cases.length}${pageMayBeIncomplete ? '+' : ''})` : ''}
          </h3>
          <p className="mt-0.5 text-xs text-fg-subtle">
            {pageMayBeIncomplete
              ? 'Real persisted Cases citing this alert -- current page, more may exist.'
              : 'Real persisted Cases citing this alert.'}
          </p>
        </div>
      </div>

      {isPending ? (
        <div className="px-5 pb-5">
          <Skeleton className="h-12 w-full" />
        </div>
      ) : isError ? (
        <div className="px-5 pb-5">
          <p className="text-xs text-fg-subtle">
            Linked cases could not be loaded.{' '}
            <button type="button" onClick={() => refetch()} className="font-medium text-accent-strong hover:text-accent">
              Retry
            </button>
          </p>
        </div>
      ) : cases.length === 0 ? (
        <EmptyState icon={FolderKanban} title="No Cases linked to this Alert." />
      ) : (
        <ul className="divide-y divide-border-faint">
          {cases.map((c: CaseRead) => (
            <li key={c.id}>
              <Link
                to={`/cases/${c.id}`}
                className="flex flex-col gap-1.5 px-5 py-3 transition-colors duration-fast hover:bg-surface-hover sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0">
                  <p className="font-mono text-xs text-fg-subtle">Case #{c.case_number}</p>
                  <p className="truncate text-sm font-medium text-accent-strong">{c.title}</p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={STATUS_TONE[c.status]}>{c.status}</Badge>
                  <Badge tone={c.priority}>{c.priority} priority</Badge>
                  {c.severity && <Badge tone={c.severity} dot>{c.severity}</Badge>}
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
