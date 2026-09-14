import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Card } from '@/components/ui/Card'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { useEventDetail } from '@/features/events/useEventDetail'
import { EventEvidenceFields } from '@/features/events/components/EventEvidenceFields'
import { LinkedAlertsPanel } from '@/features/events/components/LinkedAlertsPanel'

export function EventDetailPage() {
  const { eventId } = useParams<{ eventId: string }>()
  const navigate = useNavigate()
  const { data: event, isPending, isError, refetch } = useEventDetail(eventId)

  return (
    <div className="mx-auto max-w-[900px] px-6 py-6">
      <button
        type="button"
        onClick={() => navigate('/events')}
        className="mb-4 flex items-center gap-1.5 text-xs text-fg-subtle transition-colors duration-fast hover:text-fg"
      >
        <ArrowLeft className="size-3.5" strokeWidth={2} aria-hidden="true" />
        Back to Events
      </button>

      {isPending && (
        <Card className="p-6">
          <Skeleton className="h-6 w-64" />
          <Skeleton className="mt-6 h-24 w-full" />
        </Card>
      )}

      {isError && !isPending && (
        <Card>
          <ErrorState title="Unable to retrieve this event" onRetry={() => refetch()} />
        </Card>
      )}

      {event && (
        <Card className="p-6">
          {/* REAL BACKEND DATA -- every field below is GET /events/{id} verbatim. */}
          <p className="font-mono text-sm font-semibold text-fg">{event.event_type}</p>
          <p className="mt-1 text-xs text-fg-subtle">{new Date(event.event_timestamp).toLocaleString()}</p>

          <div className="mt-6 border-t border-border pt-4">
            <EventEvidenceFields event={event} />
          </div>
        </Card>
      )}

      {/* ---- Linked Alerts (Step 12Y): the AUTHORITATIVE SecurityEvent
       * -> Alert relationship, GET /events/{id}/alerts. ---- */}
      {event && (
        <Card className="mt-4 overflow-hidden">
          <LinkedAlertsPanel eventId={event.id} />
        </Card>
      )}
    </div>
  )
}
