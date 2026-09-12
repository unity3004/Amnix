import { AnimatePresence, motion } from 'motion/react'
import { Activity } from 'lucide-react'
import { EmptyState } from '@/components/ui/EmptyState'
import { formatRelativeTime } from '@/lib/format'
import type { LiveEventSummary } from '../types'

/** REAL BACKEND DATA -- every row is an actual SecurityEvent row from
 * GET /events (see deriveEventStream.ts). Only fields that actually
 * exist on SecurityEventRead are shown.
 */
export function LiveEventStreamPanel({ events, onSelect }: { events: LiveEventSummary[]; onSelect?: (id: string) => void }) {
  if (events.length === 0) {
    return (
      <EmptyState
        icon={Activity}
        title="Waiting for telemetry"
        description="Telemetry will appear here as soon as events are ingested."
      />
    )
  }

  return (
    <ul className="flex flex-col divide-y divide-border-faint">
      <AnimatePresence initial={false}>
        {events.map((event) => (
          <motion.li
            key={event.id}
            layout
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
          >
            <button
              type="button"
              onClick={() => onSelect?.(event.id)}
              className="flex w-full items-start gap-3 px-5 py-2.5 text-left transition-colors duration-fast hover:bg-surface-hover"
            >
              <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true" />
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="truncate font-mono text-xs font-medium text-fg">{event.eventType}</span>
                  <span className="shrink-0 text-[11px] text-fg-subtle">{formatRelativeTime(event.timestamp)}</span>
                </div>
                <p className="mt-0.5 truncate text-[11px] text-fg-subtle">
                  {event.hostname ?? event.source}
                  {event.username && <span> · {event.username}</span>}
                  {event.sourceIp && <span className="font-mono"> · {event.sourceIp}</span>}
                </p>
              </div>
            </button>
          </motion.li>
        ))}
      </AnimatePresence>
    </ul>
  )
}
