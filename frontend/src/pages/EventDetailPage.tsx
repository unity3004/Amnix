import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { useEventDetail } from '@/features/events/useEventDetail'

function Field({ label, value, mono = false }: { label: string; value: string | number | null | undefined; mono?: boolean }) {
  if (value === null || value === undefined || value === '') return null
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">{label}</dt>
      <dd className={`mt-0.5 text-sm text-fg ${mono ? 'font-mono' : ''}`}>{value}</dd>
    </div>
  )
}

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
        <>
          {/* REAL BACKEND DATA -- every field below is GET /events/{id} verbatim. */}
          <Card className="p-6">
            <p className="font-mono text-sm font-semibold text-fg">{event.event_type}</p>
            <p className="mt-1 text-xs text-fg-subtle">{new Date(event.event_timestamp).toLocaleString()}</p>

            <dl className="mt-6 grid grid-cols-2 gap-4 border-t border-border pt-4 sm:grid-cols-3">
              <Field label="Source" value={event.source} />
              <Field label="Source Event ID" value={event.source_event_id} mono />
              <Field label="Hostname" value={event.hostname} />
              <Field label="Username" value={event.username} />
              <Field label="Source IP" value={event.source_ip} mono />
              <Field label="Source Port" value={event.source_port} mono />
              <Field label="Destination IP" value={event.destination_ip} mono />
              <Field label="Destination Port" value={event.destination_port} mono />
              <Field label="Process Name" value={event.process_name} mono />
              <Field label="Process ID" value={event.process_id} mono />
              <Field label="Parent Process" value={event.parent_process_name} mono />
              <Field label="File Hash" value={event.file_hash} mono />
              <Field label="File Path" value={event.file_path} mono />
              <Field label="Severity (source-reported)" value={event.severity} />
              <Field label="Ingested At" value={new Date(event.created_at).toLocaleString()} />
            </dl>

            {event.command_line && (
              <div className="mt-4 border-t border-border pt-4">
                <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Command Line</p>
                <pre className="mt-1 overflow-x-auto rounded-md bg-bg-inset p-3 font-mono text-xs text-fg-muted">{event.command_line}</pre>
              </div>
            )}
          </Card>

          {Object.keys(event.raw_data ?? {}).length > 0 && (
            <Card className="mt-4">
              <CardHeader title="Raw Telemetry" subtitle="Original payload preserved at ingestion" />
              <pre className="mx-5 mb-5 overflow-x-auto rounded-md bg-bg-inset p-3 font-mono text-xs text-fg-muted">
                {JSON.stringify(event.raw_data, null, 2)}
              </pre>
            </Card>
          )}
        </>
      )}
    </div>
  )
}
