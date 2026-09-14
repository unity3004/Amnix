import { Link } from 'react-router-dom'
import { ShieldAlert } from 'lucide-react'
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
            <li key={a.id}>
              <Link
                to={`/alerts/${a.id}`}
                className="flex flex-col gap-1.5 px-5 py-3 transition-colors duration-fast hover:bg-surface-hover sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="flex min-w-0 items-center gap-3">
                  <SeverityBadge severity={a.severity} />
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-fg">{a.title}</p>
                    <p className="truncate font-mono text-[11px] text-fg-subtle">{a.rule_id}</p>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={STATUS_TONE[a.status]}>{a.status}</Badge>
                  <span className="text-xs capitalize text-fg-subtle">{a.confidence} confidence</span>
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
