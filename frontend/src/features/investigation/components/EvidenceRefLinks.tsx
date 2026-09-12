import { Link } from 'react-router-dom'

/** Renders Copilot's cited event_ref labels (e.g. "evt-1") as links to
 * the existing EventDetailPage when the ref can be resolved against
 * `eventRefMap` (see eventRefMap.ts), or as a plain, non-clickable
 * label when it can't. Never fetches anything -- `eventRefMap` is
 * built once from data the Investigation Workspace already has.
 */
export function EvidenceRefLinks({ refs, eventRefMap }: { refs: string[]; eventRefMap: Map<string, string> }) {
  if (refs.length === 0) return null
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {refs.map((ref) => {
        const eventId = eventRefMap.get(ref)
        return eventId ? (
          <Link
            key={ref}
            to={`/events/${eventId}`}
            className="rounded-sm bg-bg-inset px-1.5 py-0.5 font-mono text-[10px] text-accent-strong transition-colors duration-fast hover:bg-accent-dim"
            title="Open the cited event"
          >
            {ref}
          </Link>
        ) : (
          <span key={ref} className="rounded-sm bg-bg-inset px-1.5 py-0.5 font-mono text-[10px] text-fg-subtle" title="Reference could not be resolved">
            {ref}
          </span>
        )
      })}
    </span>
  )
}
