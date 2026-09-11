import { useNavigate } from 'react-router-dom'
import type { SecurityEventRead } from '@/types/api'

/** REAL BACKEND DATA -- every cell is a verbatim SecurityEventRead
 * field (GET /events). Less-critical columns hide below `md` so the
 * table reorganizes instead of becoming unreadable at narrow widths
 * (brief §35), rather than horizontally scrolling a 6-column table on
 * a phone.
 */
export function EventRow({ event }: { event: SecurityEventRead }) {
  const navigate = useNavigate()

  return (
    <tr
      onClick={() => navigate(`/events/${event.id}`)}
      className="cursor-pointer border-b border-border-faint transition-colors duration-fast last:border-b-0 hover:bg-surface-hover"
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
    </tr>
  )
}
