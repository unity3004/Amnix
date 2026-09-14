import { useEffect, useState } from 'react'
import { Filter, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { HUNT_ALL_TIME_LABEL, HUNT_WINDOW_OPTIONS, windowStart } from '../huntWindow'
import type { HuntFilters } from '../types'

const inputClass =
  'h-8 rounded-md border border-border bg-surface px-2 text-xs text-fg placeholder:text-fg-subtle transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none'

/** Structured filters only -- exactly the eight fields GET /events
 * supports (see types.ts's own docstring). No free-text search box: the
 * backend has no ILIKE/full-text/regex capability to back one (see the
 * Step 12X discovery report), so this deliberately does not pretend to
 * be a query language.
 */
export function HuntFilterPanel({
  filters,
  windowMinutes,
  onApply,
  onClear,
}: {
  filters: HuntFilters
  windowMinutes: number | null
  onApply: (filters: HuntFilters, windowMinutes: number | null) => void
  onClear: () => void
}) {
  const [eventType, setEventType] = useState(filters.event_type ?? '')
  const [source, setSource] = useState(filters.source ?? '')
  const [hostname, setHostname] = useState(filters.hostname ?? '')
  const [username, setUsername] = useState(filters.username ?? '')
  const [sourceIp, setSourceIp] = useState(filters.source_ip ?? '')
  const [destinationIp, setDestinationIp] = useState(filters.destination_ip ?? '')
  const [selectedWindow, setSelectedWindow] = useState<string>(windowMinutes === null ? 'all' : String(windowMinutes))

  useEffect(() => {
    setEventType(filters.event_type ?? '')
    setSource(filters.source ?? '')
    setHostname(filters.hostname ?? '')
    setUsername(filters.username ?? '')
    setSourceIp(filters.source_ip ?? '')
    setDestinationIp(filters.destination_ip ?? '')
    setSelectedWindow(windowMinutes === null ? 'all' : String(windowMinutes))
  }, [filters, windowMinutes])

  const hasActiveFilters = Boolean(
    filters.event_type || filters.source || filters.hostname || filters.username || filters.source_ip || filters.destination_ip || filters.since,
  )

  function handleApply() {
    const nextWindowMinutes = selectedWindow === 'all' ? null : Number(selectedWindow)
    onApply(
      {
        event_type: eventType.trim() || undefined,
        source: source.trim() || undefined,
        hostname: hostname.trim() || undefined,
        username: username.trim() || undefined,
        source_ip: sourceIp.trim() || undefined,
        destination_ip: destinationIp.trim() || undefined,
        since: nextWindowMinutes === null ? undefined : windowStart(nextWindowMinutes),
      },
      nextWindowMinutes,
    )
  }

  return (
    <div className="flex flex-col gap-2 border-b border-border px-5 py-3">
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-fg-subtle">
        <Filter className="size-3.5 shrink-0" strokeWidth={1.75} aria-hidden="true" />
        Structured filters -- exact match only
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <label className="sr-only" htmlFor="hunt-event-type">
          Event type
        </label>
        <input id="hunt-event-type" type="text" placeholder="Event type" value={eventType} onChange={(e) => setEventType(e.target.value)} className={`${inputClass} w-40`} />

        <label className="sr-only" htmlFor="hunt-source">
          Source
        </label>
        <input id="hunt-source" type="text" placeholder="Source" value={source} onChange={(e) => setSource(e.target.value)} className={`${inputClass} w-32`} />

        <label className="sr-only" htmlFor="hunt-hostname">
          Host
        </label>
        <input id="hunt-hostname" type="text" placeholder="Host" value={hostname} onChange={(e) => setHostname(e.target.value)} className={`${inputClass} w-32`} />

        <label className="sr-only" htmlFor="hunt-username">
          User
        </label>
        <input id="hunt-username" type="text" placeholder="User" value={username} onChange={(e) => setUsername(e.target.value)} className={`${inputClass} w-32`} />

        <label className="sr-only" htmlFor="hunt-source-ip">
          Source IP
        </label>
        <input id="hunt-source-ip" type="text" placeholder="Source IP" value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} className={`${inputClass} w-32 font-mono`} />

        <label className="sr-only" htmlFor="hunt-destination-ip">
          Destination IP
        </label>
        <input
          id="hunt-destination-ip"
          type="text"
          placeholder="Destination IP"
          value={destinationIp}
          onChange={(e) => setDestinationIp(e.target.value)}
          className={`${inputClass} w-32 font-mono`}
        />

        <label className="sr-only" htmlFor="hunt-window">
          Time window
        </label>
        <select id="hunt-window" className={inputClass} value={selectedWindow} onChange={(e) => setSelectedWindow(e.target.value)}>
          {HUNT_WINDOW_OPTIONS.map((w) => (
            <option key={w.label} value={String(w.minutes)}>
              {w.label}
            </option>
          ))}
          <option value="all">{HUNT_ALL_TIME_LABEL}</option>
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
    </div>
  )
}
