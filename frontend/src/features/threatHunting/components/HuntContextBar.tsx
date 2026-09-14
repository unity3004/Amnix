import { X } from 'lucide-react'
import { PIVOT_FIELDS, type HuntFilters } from '../types'
import { HUNT_ALL_TIME_LABEL, HUNT_WINDOW_OPTIONS } from '../huntWindow'

/** "Current Hunt" -- the analyst's own in-progress working context:
 * which real, backend-applied filters are active right now, and how
 * many events THIS bounded query actually returned. Explicitly analyst
 * working state, not persisted anywhere (no hunt is saved/named/shared
 * -- see this feature's own top-level docstring) -- clearing this
 * context loses nothing on the backend, because nothing was written to
 * it in the first place.
 */
export function HuntContextBar({
  filters,
  windowMinutes,
  eventCount,
  hasNextPage,
  onRemoveFilter,
}: {
  filters: HuntFilters
  windowMinutes: number | null
  eventCount: number
  hasNextPage: boolean
  onRemoveFilter: (key: keyof HuntFilters) => void
}) {
  const activeChips = PIVOT_FIELDS.filter((f) => Boolean(filters[f.filterKey]))
  const windowLabel = windowMinutes === null ? HUNT_ALL_TIME_LABEL : HUNT_WINDOW_OPTIONS.find((w) => w.minutes === windowMinutes)?.label ?? HUNT_ALL_TIME_LABEL

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-bg-inset px-5 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wide text-fg-subtle">Current Hunt</span>
        <span className="text-[11px] text-fg-subtle">Time window: {windowLabel}</span>
        {activeChips.length === 0 ? (
          <span className="text-[11px] text-fg-subtle">No active filters</span>
        ) : (
          activeChips.map((f) => (
            <span key={f.key} className="flex items-center gap-1 rounded-full border border-accent/30 bg-accent-dim px-2 py-0.5 text-[11px] text-accent-strong">
              {f.label}: {filters[f.filterKey]}
              <button type="button" onClick={() => onRemoveFilter(f.filterKey)} aria-label={`Remove ${f.label} filter`} className="hover:text-accent">
                <X className="size-3" strokeWidth={2.5} aria-hidden="true" />
              </button>
            </span>
          ))
        )}
      </div>
      <span className="text-[11px] text-fg-subtle" title="The number of events THIS bounded query returned -- never a total across the environment">
        Events returned: {eventCount}
        {hasNextPage ? '+' : ''} (this page)
      </span>
    </div>
  )
}
