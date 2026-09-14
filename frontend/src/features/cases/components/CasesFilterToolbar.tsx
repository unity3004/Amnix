import { useEffect, useState } from 'react'
import { Filter, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { CASE_PRIORITY_VALUES, CASE_STATUS_VALUES, type CasesFilters } from '../types'

const selectClass =
  'h-8 rounded-md border border-border bg-surface px-2 text-xs text-fg-muted transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none'

export function CasesFilterToolbar({
  filters,
  onApply,
  onClear,
}: {
  filters: CasesFilters
  onApply: (filters: CasesFilters) => void
  onClear: () => void
}) {
  const [status, setStatus] = useState(filters.status ?? '')
  const [priority, setPriority] = useState(filters.priority ?? '')
  const [ownerId, setOwnerId] = useState(filters.owner_id ?? '')

  useEffect(() => {
    setStatus(filters.status ?? '')
    setPriority(filters.priority ?? '')
    setOwnerId(filters.owner_id ?? '')
  }, [filters])

  const hasActiveFilters = Boolean(filters.status || filters.priority || filters.owner_id)

  function handleApply() {
    onApply({
      status: (status || undefined) as CasesFilters['status'],
      priority: (priority || undefined) as CasesFilters['priority'],
      owner_id: ownerId.trim() || undefined,
    })
  }

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border px-5 py-3">
      <Filter className="size-3.5 shrink-0 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />

      <label className="sr-only" htmlFor="cases-status-filter">
        Status
      </label>
      <select id="cases-status-filter" className={selectClass} value={status} onChange={(e) => setStatus(e.target.value)}>
        <option value="">Status: Any</option>
        {CASE_STATUS_VALUES.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>

      <label className="sr-only" htmlFor="cases-priority-filter">
        Priority
      </label>
      <select id="cases-priority-filter" className={selectClass} value={priority} onChange={(e) => setPriority(e.target.value)}>
        <option value="">Priority: Any</option>
        {CASE_PRIORITY_VALUES.map((p) => (
          <option key={p} value={p}>
            {p}
          </option>
        ))}
      </select>

      <label className="sr-only" htmlFor="cases-owner-filter">
        Owner ID
      </label>
      <input
        id="cases-owner-filter"
        type="text"
        placeholder="Owner UUID"
        value={ownerId}
        onChange={(e) => setOwnerId(e.target.value)}
        className="h-8 w-40 rounded-md border border-border bg-surface px-2 font-mono text-xs text-fg placeholder:text-fg-subtle transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none"
      />

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
