import { useEffect, useState } from 'react'
import { Filter, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import type { EventsFilters } from '../types'

const TIME_RANGE_OPTIONS = [
  { label: 'Last hour', hours: 1 },
  { label: 'Last 24 hours', hours: 24 },
  { label: 'Last 7 days', hours: 24 * 7 },
] as const

function hoursToSince(hours: number): string {
  return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString()
}

const inputClass =
  'h-8 rounded-md border border-border bg-surface px-2 text-xs text-fg placeholder:text-fg-subtle transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none'

export function EventsFilterToolbar({ filters, onApply, onClear }: { filters: EventsFilters; onApply: (filters: EventsFilters) => void; onClear: () => void }) {
  const [eventType, setEventType] = useState(filters.event_type ?? '')
  const [source, setSource] = useState(filters.source ?? '')
  const [rangeHours, setRangeHours] = useState<string>('')

  useEffect(() => {
    setEventType(filters.event_type ?? '')
    setSource(filters.source ?? '')
    if (!filters.since) setRangeHours('')
  }, [filters])

  const hasActiveFilters = Boolean(filters.event_type || filters.source || filters.since || filters.until)

  function handleApply() {
    onApply({
      event_type: eventType.trim() || undefined,
      source: source.trim() || undefined,
      since: rangeHours ? hoursToSince(Number(rangeHours)) : filters.since,
    })
  }

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border px-5 py-3">
      <Filter className="size-3.5 shrink-0 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />

      <label className="sr-only" htmlFor="events-type-filter">
        Event type
      </label>
      <input
        id="events-type-filter"
        type="text"
        placeholder="Event type"
        value={eventType}
        onChange={(e) => setEventType(e.target.value)}
        className={`${inputClass} w-40`}
      />

      <label className="sr-only" htmlFor="events-source-filter">
        Source
      </label>
      <input
        id="events-source-filter"
        type="text"
        placeholder="Source"
        value={source}
        onChange={(e) => setSource(e.target.value)}
        className={`${inputClass} w-40`}
      />

      <label className="sr-only" htmlFor="events-range-filter">
        Time range
      </label>
      <select
        id="events-range-filter"
        className="h-8 rounded-md border border-border bg-surface px-2 text-xs text-fg-muted transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none"
        value={rangeHours}
        onChange={(e) => setRangeHours(e.target.value)}
      >
        <option value="">Time range: All</option>
        {TIME_RANGE_OPTIONS.map((r) => (
          <option key={r.label} value={String(r.hours)}>
            {r.label}
          </option>
        ))}
      </select>

      <Button variant="primary" size="sm" onClick={handleApply}>
        Apply
      </Button>
      {hasActiveFilters && (
        <Button variant="ghost" size="sm" onClick={onClear}>
          <X className="size-3.5" strokeWidth={2} aria-hidden="true" />
          Clear
        </Button>
      )}
    </div>
  )
}
