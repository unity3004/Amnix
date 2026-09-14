import { useMemo, useState } from 'react'
import { ArrowDownUp, FileText, FlaskConical, Link2, ScrollText, ShieldAlert, StickyNote, User } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { cn } from '@/lib/cn'
import { formatRelativeTime } from '@/lib/format'
import type { IncidentTimelineCategory, IncidentTimelineEntry } from '../logic'

const CATEGORY_ICON: Record<IncidentTimelineCategory, typeof ShieldAlert> = {
  Alerts: ShieldAlert,
  Investigation: FlaskConical,
  Notes: StickyNote,
  Audit: ScrollText,
  Copilot: FileText,
  Status: ArrowDownUp,
  Owner: User,
}

const FILTERS: Array<'All' | IncidentTimelineCategory> = ['All', 'Alerts', 'Investigation', 'Notes', 'Audit', 'Copilot', 'Status', 'Owner']

/** The incident timeline centerpiece -- entries are pre-merged/sorted by
 * buildIncidentTimeline() (see logic.ts); this component only filters
 * (client-side, no extra request) and optionally reverses the already-
 * fetched array. Category chips are hidden when their real count is
 * zero, so the filter bar never advertises a filter with nothing behind it.
 */
export function IncidentTimelinePanel({ entries, focusedAlertLoaded }: { entries: IncidentTimelineEntry[]; focusedAlertLoaded: boolean }) {
  const [filter, setFilter] = useState<'All' | IncidentTimelineCategory>('All')
  const [oldestFirst, setOldestFirst] = useState(false)

  const counts = useMemo(() => {
    const map = new Map<string, number>()
    for (const e of entries) map.set(e.category, (map.get(e.category) ?? 0) + 1)
    return map
  }, [entries])

  const visible = useMemo(() => {
    const filtered = filter === 'All' ? entries : entries.filter((e) => e.category === filter)
    return oldestFirst ? [...filtered].reverse() : filtered
  }, [entries, filter, oldestFirst])

  return (
    <Card id="console-timeline" className="scroll-mt-20 overflow-hidden">
      <CardHeader
        title="Incident Timeline"
        subtitle={
          focusedAlertLoaded
            ? 'Merged from case audit, notes, the focused alert\'s investigation, and its Copilot activity.'
            : 'Merged from case audit and notes -- select an alert below to add its investigation/Copilot activity.'
        }
        action={
          <Button variant="ghost" size="sm" onClick={() => setOldestFirst((v) => !v)}>
            <ArrowDownUp className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            {oldestFirst ? 'Oldest first' : 'Newest first'}
          </Button>
        }
      />

      <div className="flex flex-wrap gap-1.5 border-b border-border px-5 pb-3">
        {FILTERS.filter((f) => f === 'All' || (counts.get(f) ?? 0) > 0).map((f) => (
          <button
            key={f}
            type="button"
            onClick={() => setFilter(f)}
            className={cn(
              'rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors duration-fast',
              filter === f ? 'border-accent/40 bg-accent-dim text-accent-strong' : 'border-border-strong text-fg-subtle hover:bg-surface-hover',
            )}
          >
            {f}
            {f !== 'All' && <span className="ml-1 opacity-70">{counts.get(f) ?? 0}</span>}
          </button>
        ))}
      </div>

      {visible.length === 0 ? (
        <EmptyState icon={Link2} title="No timeline entries match this filter." />
      ) : (
        <ul className="divide-y divide-border-faint">
          {visible.map((entry) => {
            const Icon = CATEGORY_ICON[entry.category]
            return (
              <li key={entry.id} className="flex gap-3 px-5 py-3">
                <div className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full border border-border-strong bg-surface-elevated">
                  <Icon className="size-3.5 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-sm font-medium text-fg">{entry.title}</p>
                    <span className="shrink-0 text-[11px] text-fg-subtle" title={new Date(entry.timestamp).toLocaleString()}>
                      {formatRelativeTime(entry.timestamp)}
                    </span>
                  </div>
                  {entry.description && <p className="mt-0.5 text-xs text-fg-subtle">{entry.description}</p>}
                  <p className="mt-1 flex items-center gap-2 text-[11px] text-fg-subtle">
                    <span className="rounded-sm border border-border-faint px-1 py-0.5">{entry.category}</span>
                    {entry.actor && (
                      <span className="font-mono" title={entry.actor}>
                        by {entry.actor}
                      </span>
                    )}
                  </p>
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </Card>
  )
}
