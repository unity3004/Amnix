import { Link } from 'react-router-dom'
import { ArrowRight, Crosshair } from 'lucide-react'
import { CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { EventEvidenceFields } from '@/features/events/components/EventEvidenceFields'
import { PIVOT_FIELDS, type HuntFilters } from '../types'
import type { SecurityEventRead } from '@/types/api'

/** "Inspect Event" + "Pivot from Event" -- both operate on the ALREADY-
 * fetched focused event (zero additional requests; see
 * useThreatHuntQuery's own docstring for why GET /events already
 * returns full-fidelity rows). Each pivot button uses the event's own
 * REAL field value and only exists when that value is actually present
 * -- there is no button for a null field, and no button for any field
 * GET /events can't filter on (see types.ts's own docstring on why
 * process_name/file_hash/etc have no pivot here).
 *
 * "Open Full Event Detail" is a real, existing route (EventDetailPage)
 * -- a permalink into the same evidence, not a duplicate rendering of
 * it. There is deliberately no "Open Alert"/"Open Case" action here:
 * discovery confirmed no reverse Event -> Alert relationship endpoint
 * exists in AMNIX today, so showing one would be a fabricated
 * relationship (see the Step 12X completion report's own Limitations
 * section).
 */
export function EventInspectorPanel({
  event,
  onPivot,
}: {
  event: SecurityEventRead | undefined
  onPivot: (filterKey: keyof HuntFilters, value: string) => void
}) {
  return (
    <div className="rounded-lg border border-border bg-surface">
      <CardHeader title="Event Inspector" subtitle={event ? 'Selected from the current hunt results' : 'Select an event to inspect it'} />

      {!event ? (
        <div className="px-5 pb-5">
          <EmptyState icon={Crosshair} title="No event selected." description="Click a row in the results table to inspect its evidence." />
        </div>
      ) : (
        <div className="flex flex-col gap-4 px-5 pb-5">
          <div>
            <p className="font-mono text-sm font-semibold text-fg">{event.event_type}</p>
            <p className="mt-1 text-xs text-fg-subtle">{new Date(event.event_timestamp).toLocaleString()}</p>
          </div>

          <div>
            <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Pivot From Event</p>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {PIVOT_FIELDS.map((f) => {
                const value = event[f.key as keyof SecurityEventRead]
                if (!value || typeof value !== 'string') return null
                return (
                  <Button key={f.key} type="button" variant="secondary" size="sm" onClick={() => onPivot(f.filterKey, value)}>
                    <Crosshair className="size-3 shrink-0" strokeWidth={2} aria-hidden="true" />
                    Same {f.label}
                  </Button>
                )
              })}
            </div>
          </div>

          <div className="border-t border-border pt-4">
            <EventEvidenceFields event={event} />
          </div>

          <Link to={`/events/${event.id}`} className="inline-flex items-center gap-1.5 text-xs font-medium text-accent-strong hover:text-accent">
            Open Full Event Detail
            <ArrowRight className="size-3.5" strokeWidth={2} aria-hidden="true" />
          </Link>
        </div>
      )}
    </div>
  )
}
