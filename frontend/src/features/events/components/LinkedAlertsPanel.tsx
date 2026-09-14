import { Link } from 'react-router-dom'
import { ArrowRight, FileSearch, ShieldAlert } from 'lucide-react'
import { SeverityBadge, Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { Skeleton } from '@/components/ui/Skeleton'
import { useEventAlerts } from '@/features/events/useEventAlerts'
import type { AlertRead, AlertStatus } from '@/types/api'

const STATUS_TONE: Record<AlertStatus, 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

const PAGE_SIZE = 50

/** GET /events/{id}/alerts (Step 12Y) -- the AUTHORITATIVE SecurityEvent
 * -> Alert relationship, the mirror image of LinkedCasesPanel's own
 * GET /alerts/{id}/cases (Step 12V) one hop over. Never derived from
 * rule_id/timestamp/hostname/username/IP/text matching -- the backend's
 * own alert_security_events join is the sole source of truth.
 *
 * An event can be evidence for zero, one, or multiple alerts; this panel
 * never assumes exactly one. The empty state deliberately says "No
 * alerts are linked to this event" -- never "No threats detected": the
 * absence of a linked alert does not mean the event was reviewed and
 * found benign, only that no Alert currently cites it.
 *
 * Shared between EventDetailPage and the Step 12X Threat Hunting Event
 * Inspector so alert-relationship rendering is never duplicated. Reused,
 * not reinvented, exactly like EventEvidenceFields.
 *
 * Step 12Z: each row exposes two explicit, real navigation actions --
 * "Open Alert" (`/alerts/{id}`) and "Investigate" (`/alerts/{id}/
 * investigation`, the existing Investigation Workspace) -- mirroring
 * CaseAlertsPanel's own dual-action row shape (Step 12S). Neither ever
 * fires a request on render: Investigation only loads once the analyst
 * actually clicks through, exactly like every other entry point into it.
 * There is no case-navigation context to preserve here (an event/hunt
 * has no Case unless a linked Alert already has one, visible via that
 * Alert's own Linked Cases panel one click away) -- see
 * caseNavigationContext.ts's own docstring for why that mechanism is
 * Case-scoped only, never fabricated for a hunt-originated visit.
 */
export function LinkedAlertsPanel({ eventId }: { eventId: string }) {
  const { data, isPending, isError, refetch } = useEventAlerts(eventId)
  const alerts = data?.items ?? []
  const pageMayBeIncomplete = alerts.length === PAGE_SIZE

  return (
    <div>
      <div className="flex items-center justify-between px-5 pt-4 pb-2">
        <div>
          <h3 className="text-sm font-semibold tracking-wide text-fg">
            Linked Alerts{!isPending && !isError && alerts.length > 0 ? ` (${alerts.length}${pageMayBeIncomplete ? '+' : ''})` : ''}
          </h3>
          <p className="mt-0.5 text-xs text-fg-subtle">
            {pageMayBeIncomplete
              ? 'Real persisted Alerts citing this event as evidence -- current page, more may exist.'
              : 'Real persisted Alerts citing this event as evidence.'}
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
            Linked alerts could not be loaded.{' '}
            <button type="button" onClick={() => refetch()} className="font-medium text-accent-strong hover:text-accent">
              Retry
            </button>
          </p>
        </div>
      ) : alerts.length === 0 ? (
        <EmptyState icon={ShieldAlert} title="No alerts are linked to this event." />
      ) : (
        <ul className="divide-y divide-border-faint">
          {alerts.map((a: AlertRead) => (
            <li key={a.id} className="flex flex-col gap-2 px-5 py-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex min-w-0 items-center gap-3">
                <SeverityBadge severity={a.severity} />
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-fg">{a.title}</p>
                  <p className="truncate font-mono text-[11px] text-fg-subtle">{a.rule_id}</p>
                </div>
              </div>
              <div className="flex shrink-0 flex-wrap items-center gap-2">
                <Badge tone={STATUS_TONE[a.status]}>{a.status}</Badge>
                <span className="text-xs capitalize text-fg-subtle">{a.confidence} confidence</span>
                <Link
                  to={`/alerts/${a.id}`}
                  className="flex items-center gap-1 rounded-md border border-border-strong px-2 py-1 text-xs font-medium text-fg-muted transition-colors duration-fast hover:border-accent/40 hover:bg-surface-hover hover:text-accent-strong"
                >
                  <ArrowRight className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                  Open Alert
                </Link>
                <Link
                  to={`/alerts/${a.id}/investigation`}
                  className="flex items-center gap-1 rounded-md border border-border-strong px-2 py-1 text-xs font-medium text-fg-muted transition-colors duration-fast hover:border-accent/40 hover:bg-surface-hover hover:text-accent-strong"
                  title="Open the Investigation Workspace for this alert -- fetches investigation data only when you click through, never automatically"
                >
                  <FileSearch className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                  Investigate
                </Link>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
