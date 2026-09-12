import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import { CardHeader } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { FileSearch } from 'lucide-react'
import type { TimelineEntry } from '@/types/api'

function Chip({ label, value, mono = false }: { label: string; value: string | null; mono?: boolean }) {
  if (!value) return null
  return (
    <span className="inline-flex items-center gap-1 rounded-sm bg-bg-inset px-1.5 py-0.5 text-[11px] text-fg-muted">
      <span className="text-fg-subtle">{label}</span>
      <span className={mono ? 'font-mono' : ''}>{value}</span>
    </span>
  )
}

/** Section C: related events / evidence. Sourced entirely from
 * InvestigationContext.timeline -- REAL BACKEND DATA already embedded
 * in the one GET /alerts/{id}/investigation response this page fetched,
 * so rendering every event here costs zero additional HTTP requests
 * (see brief Phase 5's explicit N+1 requirement). Each row only shows
 * fields actually present on that TimelineEntry; nothing is invented
 * for events missing hostname/user/IP/process data. Clicking a row
 * navigates to the existing EventDetailPage via the event's real id --
 * no new detail view is built here.
 */
export function EvidencePanel({ timeline }: { timeline: TimelineEntry[] }) {
  return (
    <div className="overflow-hidden">
      <CardHeader title="Evidence / Related Events" subtitle={`${timeline.length} related event(s) cited as evidence`} />
      {timeline.length === 0 ? (
        <EmptyState icon={FileSearch} title="No related events" description="This alert has no associated security events." />
      ) : (
        <ul className="divide-y divide-border-faint">
          {timeline.map((entry) => (
            <li key={entry.event_id}>
              <Link
                to={`/events/${entry.event_id}`}
                className="block px-5 py-3 transition-colors duration-fast hover:bg-surface-hover"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-medium text-fg">{entry.event_type}</span>
                  <div className="flex items-center gap-2 text-[11px] text-fg-subtle">
                    {new Date(entry.event_timestamp).toLocaleString()}
                    <ArrowRight className="size-3.5 shrink-0" strokeWidth={2} aria-hidden="true" />
                  </div>
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  <Chip label="source" value={entry.source} />
                  <Chip label="host" value={entry.hostname} />
                  <Chip label="user" value={entry.username} />
                  <Chip label="src ip" value={entry.source_ip} mono />
                  <Chip label="dst ip" value={entry.destination_ip} mono />
                  <Chip label="process" value={entry.process_name} mono />
                </div>
                {entry.command_line && (
                  <p className="mt-1.5 truncate font-mono text-[11px] text-fg-subtle" title={entry.command_line}>
                    {entry.command_line}
                  </p>
                )}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
