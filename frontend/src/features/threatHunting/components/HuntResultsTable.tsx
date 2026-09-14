import { cn } from '@/lib/cn'
import type { SecurityEventRead } from '@/types/api'

const COLUMN_HEADERS = [
  { label: 'Timestamp', className: '' },
  { label: 'Event Type', className: '' },
  { label: 'Source', className: 'hidden sm:table-cell' },
  { label: 'Host', className: 'hidden md:table-cell' },
  { label: 'User', className: 'hidden md:table-cell' },
  { label: 'Source IP', className: 'hidden lg:table-cell' },
  { label: 'Destination IP', className: 'hidden lg:table-cell' },
]

/** REAL BACKEND DATA -- every cell is a verbatim SecurityEventRead
 * field from the one GET /events request this hunt already made (see
 * useThreatHuntQuery). Clicking a row selects it as the focused event
 * for the inspector below -- no navigation, no additional fetch (the
 * row already IS the full SecurityEventRead the inspector needs).
 */
export function HuntResultsTable({
  events,
  focusedEventId,
  onSelectEvent,
}: {
  events: SecurityEventRead[]
  focusedEventId: string | undefined
  onSelectEvent: (event: SecurityEventRead) => void
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr className="border-b border-border text-left">
            {COLUMN_HEADERS.map((col) => (
              <th key={col.label} className={`px-5 py-2 text-[11px] font-medium uppercase tracking-wide text-fg-subtle first:px-5 ${col.className}`}>
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr
              key={event.id}
              onClick={() => onSelectEvent(event)}
              aria-selected={focusedEventId === event.id}
              className={cn(
                'cursor-pointer border-b border-border-faint transition-colors duration-fast last:border-b-0 hover:bg-surface-hover',
                focusedEventId === event.id && 'bg-accent-dim/40',
              )}
            >
              <td className="whitespace-nowrap px-5 py-2.5 font-mono text-xs text-fg-muted">
                {new Date(event.event_timestamp).toLocaleTimeString(undefined, { hour12: false })}
                <span className="ml-1.5 text-fg-subtle">{new Date(event.event_timestamp).toLocaleDateString()}</span>
              </td>
              <td className="px-3 py-2.5 font-mono text-xs font-medium text-fg">{event.event_type}</td>
              <td className="hidden px-3 py-2.5 text-xs text-fg-muted sm:table-cell">{event.source}</td>
              <td className="hidden px-3 py-2.5 text-xs text-fg-muted md:table-cell">{event.hostname ?? '—'}</td>
              <td className="hidden px-3 py-2.5 text-xs text-fg-muted md:table-cell">{event.username ?? '—'}</td>
              <td className="hidden px-3 py-2.5 font-mono text-xs text-fg-muted lg:table-cell">{event.source_ip ?? '—'}</td>
              <td className="hidden px-3 py-2.5 font-mono text-xs text-fg-muted lg:table-cell">{event.destination_ip ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
