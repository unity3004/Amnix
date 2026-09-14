import type { SecurityEventRead } from '@/types/api'

function Field({ label, value, mono = false }: { label: string; value: string | number | null | undefined; mono?: boolean }) {
  if (value === null || value === undefined || value === '') return null
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">{label}</dt>
      <dd className={`mt-0.5 text-sm text-fg ${mono ? 'font-mono' : ''}`}>{value}</dd>
    </div>
  )
}

/** REAL BACKEND DATA -- every field is a verbatim SecurityEventRead
 * field, GET /events or GET /events/{id} (identical shape either way --
 * the list endpoint returns the exact same full SecurityEventRead per
 * row, never a trimmed summary). Extracted from EventDetailPage (Step
 * 12X) so the Threat Hunting workspace's inline event inspector reuses
 * this exact rendering instead of duplicating it -- one place decides
 * what "the evidence for one event" looks like.
 */
export function EventEvidenceFields({ event }: { event: SecurityEventRead }) {
  return (
    <>
      <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3">
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

      {Object.keys(event.raw_data ?? {}).length > 0 && (
        <div className="mt-4 border-t border-border pt-4">
          <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Raw Telemetry</p>
          <pre className="mt-1 overflow-x-auto rounded-md bg-bg-inset p-3 font-mono text-xs text-fg-muted">
            {JSON.stringify(event.raw_data, null, 2)}
          </pre>
        </div>
      )}
    </>
  )
}
