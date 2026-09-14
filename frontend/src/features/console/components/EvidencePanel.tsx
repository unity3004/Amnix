import { Link } from 'react-router-dom'
import { ChevronDown } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { EvidenceDetailList } from '@/features/alerts/components/EvidenceDetailList'
import { FindingsPanel } from '@/features/investigation/components/FindingsPanel'
import { EVIDENCE_GROUP_ORDER, groupEvidenceByType } from '../logic'
import type { AlertRead, InvestigationContext } from '@/types/api'

/** Reuses existing evidence exactly -- EvidenceDetailList (an alert's
 * own structured evidence blob) and FindingsPanel (InvestigationContext
 * entities), both unmodified. The only new presentation here is
 * grouping the focused alert's real investigation.timeline entries by
 * event_type (Authentication/PowerShell/Process Creation/Network/Other
 * -- see classifyEventType in logic.ts, a generic substring match, never
 * a rule-specific rule). Every event links to the existing
 * EventDetailPage via its real event_id -- no synthetic reference, no
 * per-event fetch.
 */
export function EvidencePanel({
  alerts,
  focusedAlert,
  focusedAlertId,
  onFocusAlert,
  investigation,
  isInvestigationPending,
  isInvestigationError,
}: {
  alerts: AlertRead[]
  focusedAlert: AlertRead | undefined
  focusedAlertId: string | undefined
  onFocusAlert: (alertId: string) => void
  investigation: InvestigationContext | undefined
  isInvestigationPending: boolean
  isInvestigationError: boolean
}) {
  const groups = investigation ? groupEvidenceByType(investigation.timeline) : null

  return (
    <Card id="console-evidence" className="scroll-mt-20 overflow-hidden">
      <CardHeader title="Evidence" subtitle="Real evidence for one focused alert at a time -- select which." />

      {alerts.length === 0 ? (
        <div className="px-5 pb-5">
          <EmptyState title="No linked alerts to inspect evidence for." />
        </div>
      ) : (
        <>
          <div className="px-5 pb-4">
            <label className="sr-only" htmlFor="console-evidence-alert-select">
              Focused alert
            </label>
            <select
              id="console-evidence-alert-select"
              value={focusedAlertId ?? ''}
              onChange={(e) => onFocusAlert(e.target.value)}
              className="h-9 w-full rounded-md border border-border bg-surface px-2 text-sm text-fg focus:border-accent/50 focus:outline-none sm:w-auto"
            >
              {alerts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.title} ({a.severity})
                </option>
              ))}
            </select>
          </div>

          {focusedAlert && (
            <div className="border-t border-border px-5 py-4">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Observed Detection Evidence</p>
              <div className="mt-2">
                <EvidenceDetailList evidence={focusedAlert.evidence} />
              </div>
            </div>
          )}

          {focusedAlert && focusedAlert.source_event_ids.length > 0 && (
            <div className="border-t border-border px-5 py-4">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Supporting Events</p>
              <ul className="mt-2 divide-y divide-border-faint">
                {focusedAlert.source_event_ids.map((eventId) => (
                  <li key={eventId}>
                    <Link to={`/events/${eventId}`} className="block py-1.5 font-mono text-xs text-fg-muted hover:text-accent-strong">
                      {eventId}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="border-t border-border px-5 py-4">
            <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Security Events (grouped)</p>
            {isInvestigationPending ? (
              <Skeleton className="mt-2 h-16 w-full" />
            ) : isInvestigationError ? (
              <ErrorState title="Investigation data could not be loaded" />
            ) : !groups || groups.size === 0 ? (
              <p className="mt-2 text-xs text-fg-subtle">No telemetry events recorded for this alert.</p>
            ) : (
              <div className="mt-2 flex flex-col gap-2">
                {EVIDENCE_GROUP_ORDER.filter((g) => (groups.get(g)?.length ?? 0) > 0).map((groupName) => {
                  const items = groups.get(groupName) ?? []
                  return (
                    <details key={groupName} className="group rounded-md border border-border-faint bg-bg-inset">
                      <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2 text-sm font-medium text-fg">
                        {groupName}
                        <span className="flex items-center gap-2 text-xs text-fg-subtle">
                          {items.length}
                          <ChevronDown className="size-3.5 transition-transform duration-fast group-open:rotate-180" strokeWidth={2} aria-hidden="true" />
                        </span>
                      </summary>
                      <ul className="divide-y divide-border-faint border-t border-border-faint">
                        {items.map((event) => (
                          <li key={event.event_id} className="px-3 py-2 text-xs">
                            <div className="flex items-center justify-between gap-2">
                              <Link to={`/events/${event.event_id}`} className="font-mono text-accent-strong hover:text-accent">
                                {event.event_id}
                              </Link>
                              <span className="text-fg-subtle" title={new Date(event.event_timestamp).toLocaleString()}>
                                {new Date(event.event_timestamp).toLocaleTimeString()}
                              </span>
                            </div>
                            <p className="mt-0.5 text-fg-subtle">
                              {[event.hostname, event.username, event.process_name, event.source_ip].filter(Boolean).join(' · ') || event.event_type}
                            </p>
                          </li>
                        ))}
                      </ul>
                    </details>
                  )
                })}
              </div>
            )}
          </div>

          {investigation && (
            <div className="border-t border-border">
              <FindingsPanel alert={investigation.alert} investigation={investigation} />
            </div>
          )}
        </>
      )}
    </Card>
  )
}
