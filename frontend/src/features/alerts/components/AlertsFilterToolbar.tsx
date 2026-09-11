import { useEffect, useState } from 'react'
import { Filter, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ALERT_SEVERITY_VALUES, ALERT_STATUS_VALUES, type AlertsFilters } from '../types'

const TIME_RANGE_OPTIONS = [
  { label: 'All time', hours: null },
  { label: 'Last hour', hours: 1 },
  { label: 'Last 24 hours', hours: 24 },
  { label: 'Last 7 days', hours: 24 * 7 },
] as const

function hoursToSince(hours: number | null): string | undefined {
  if (hours === null) return undefined
  return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString()
}

const selectClass =
  'h-8 rounded-md border border-border bg-surface px-2 text-xs text-fg-muted transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none'

export function AlertsFilterToolbar({ filters, onApply, onClear }: { filters: AlertsFilters; onApply: (filters: AlertsFilters) => void; onClear: () => void }) {
  const [status, setStatus] = useState(filters.status ?? '')
  const [severity, setSeverity] = useState(filters.severity ?? '')
  const [ruleId, setRuleId] = useState(filters.rule_id ?? '')
  const [rangeHours, setRangeHours] = useState<string>('')

  useEffect(() => {
    setStatus(filters.status ?? '')
    setSeverity(filters.severity ?? '')
    setRuleId(filters.rule_id ?? '')
    if (!filters.since) setRangeHours('')
  }, [filters])

  const hasActiveFilters = Boolean(filters.status || filters.severity || filters.rule_id || filters.since || filters.until)

  function handleApply() {
    const selectedRange = TIME_RANGE_OPTIONS.find((r) => String(r.hours) === rangeHours)
    onApply({
      status: (status || undefined) as AlertsFilters['status'],
      severity: (severity || undefined) as AlertsFilters['severity'],
      rule_id: ruleId.trim() || undefined,
      since: selectedRange ? hoursToSince(selectedRange.hours) : filters.since,
    })
  }

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border px-5 py-3">
      <Filter className="size-3.5 shrink-0 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />

      <label className="sr-only" htmlFor="alerts-status-filter">
        Status
      </label>
      <select id="alerts-status-filter" className={selectClass} value={status} onChange={(e) => setStatus(e.target.value)}>
        <option value="">Status: Any</option>
        {ALERT_STATUS_VALUES.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>

      <label className="sr-only" htmlFor="alerts-severity-filter">
        Severity
      </label>
      <select id="alerts-severity-filter" className={selectClass} value={severity} onChange={(e) => setSeverity(e.target.value)}>
        <option value="">Severity: Any</option>
        {ALERT_SEVERITY_VALUES.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>

      <label className="sr-only" htmlFor="alerts-rule-filter">
        Rule ID
      </label>
      <input
        id="alerts-rule-filter"
        type="text"
        placeholder="Rule ID"
        value={ruleId}
        onChange={(e) => setRuleId(e.target.value)}
        className="h-8 w-40 rounded-md border border-border bg-surface px-2 text-xs text-fg placeholder:text-fg-subtle transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none"
      />

      <label className="sr-only" htmlFor="alerts-range-filter">
        Time range
      </label>
      <select id="alerts-range-filter" className={selectClass} value={rangeHours} onChange={(e) => setRangeHours(e.target.value)}>
        <option value="">Time range: All</option>
        {TIME_RANGE_OPTIONS.filter((r) => r.hours !== null).map((r) => (
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
