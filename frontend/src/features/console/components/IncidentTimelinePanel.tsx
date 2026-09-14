import { useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ArrowDownUp, ArrowRight, FileText, FlaskConical, Link2, ScrollText, ShieldAlert, StickyNote, User } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { cn } from '@/lib/cn'
import { formatRelativeTime } from '@/lib/format'
import { buildCaseContextQuery } from '@/features/cases/caseNavigationContext'
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
 *
 * Step 13B: shared verbatim by CaseTimelinePanel (features/cases) for
 * CaseDetailPage's own Case Investigation Timeline -- see logic.ts's own
 * top-of-file note. `caseId`/`caseNumber`, when supplied, are used only
 * to carry the existing Step 12U case-navigation-context query string on
 * an entry's Alert link (`entry.navigateTo` starting with `/alerts/`);
 * Event links never take case context (Event Detail has no such
 * concept). Never fetches anything -- `navigateTo` was already computed
 * by buildIncidentTimeline() from real, already-loaded data.
 *
 * `alertSelector`, when supplied, renders inside this SAME Card (between
 * the header and the filter chips) -- the one seam CaseTimelinePanel
 * uses to add its "which alert's telemetry to include" control without
 * this becoming two separately-styled timeline surfaces. Console never
 * passes it, so Console's own rendering is byte-for-byte unchanged.
 */
export function IncidentTimelinePanel({
  entries,
  focusedAlertLoaded,
  caseId,
  caseNumber,
  alertSelector,
}: {
  entries: IncidentTimelineEntry[]
  focusedAlertLoaded: boolean
  caseId?: string
  caseNumber?: number
  alertSelector?: ReactNode
}) {
  const [filter, setFilter] = useState<'All' | IncidentTimelineCategory>('All')
  const [oldestFirst, setOldestFirst] = useState(false)
  const caseContextQuery = caseId && caseNumber !== undefined ? buildCaseContextQuery({ caseId, caseNumber }) : ''

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
            ? "Assembled from case audit, notes, the focused alert's investigation, and its Copilot activity -- not a persisted historical event stream, and not guaranteed to be complete."
            : 'Assembled from case audit and notes -- select an alert below to add its investigation/Copilot activity. Not a persisted historical event stream.'
        }
        action={
          <Button variant="ghost" size="sm" onClick={() => setOldestFirst((v) => !v)}>
            <ArrowDownUp className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            {oldestFirst ? 'Oldest first' : 'Newest first'}
          </Button>
        }
      />

      {alertSelector}

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
                  <p className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-fg-subtle">
                    <span className="rounded-sm border border-border-faint px-1 py-0.5">{entry.category}</span>
                    {entry.actor && (
                      <span className="font-mono" title={entry.actor}>
                        by {entry.actor}
                      </span>
                    )}
                    {entry.navigateTo && (
                      <Link
                        to={entry.navigateTo.startsWith('/alerts/') ? `${entry.navigateTo}${caseContextQuery}` : entry.navigateTo}
                        className="ml-auto flex items-center gap-1 font-medium text-accent-strong hover:text-accent"
                      >
                        {entry.navigateTo.startsWith('/alerts/') ? 'Open Alert' : 'Open Event'}
                        <ArrowRight className="size-3 shrink-0" strokeWidth={2} aria-hidden="true" />
                      </Link>
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
