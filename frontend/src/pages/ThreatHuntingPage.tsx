import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Crosshair } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { SkeletonRow } from '@/components/ui/Skeleton'
import { Pagination } from '@/components/ui/Pagination'
import { LiveIndicator } from '@/components/live/LiveIndicator'
import { RefreshButton } from '@/components/live/RefreshButton'
import { HuntFilterPanel } from '@/features/threatHunting/components/HuntFilterPanel'
import { HuntContextBar } from '@/features/threatHunting/components/HuntContextBar'
import { HuntResultsTable } from '@/features/threatHunting/components/HuntResultsTable'
import { EventInspectorPanel } from '@/features/threatHunting/components/EventInspectorPanel'
import { useThreatHuntQuery } from '@/features/threatHunting/useThreatHuntQuery'
import { windowStart } from '@/features/threatHunting/huntWindow'
import type { HuntFilters } from '@/features/threatHunting/types'
import type { SecurityEventRead } from '@/types/api'

/** AMNIX SOC Threat Hunting Workspace (Step 12X).
 *
 * Orchestrates the existing GET /events surface (now with Step 12X's
 * four additional exact-match filters) into an investigation-oriented
 * workflow: search -> inspect -> pivot -> repeat, entirely client-side
 * after the one bounded query each search issues. Reuses EventEvidenceFields
 * (shared with EventDetailPage) for the inspector, so evidence rendering
 * is never duplicated.
 *
 * "Current Hunt" (active filters, time window, events-returned count)
 * is deliberately ephemeral, URL-mirrored working state -- the same
 * pattern every other AMNIX list page (Alerts/Events/Cases) already
 * uses for its own filters, not a new persistence layer. No hunt is
 * named, saved, or written to the backend.
 */
export function ThreatHuntingPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [focusedEvent, setFocusedEvent] = useState<SecurityEventRead | undefined>(undefined)

  const page = Math.max(1, Number(searchParams.get('page') ?? '1') || 1)
  const windowParam = searchParams.get('window')
  const windowMinutes = windowParam === 'all' ? null : windowParam ? Number(windowParam) : 60

  const filters: HuntFilters = useMemo(
    () => ({
      event_type: searchParams.get('event_type') || undefined,
      source: searchParams.get('source') || undefined,
      hostname: searchParams.get('hostname') || undefined,
      username: searchParams.get('username') || undefined,
      source_ip: searchParams.get('source_ip') || undefined,
      destination_ip: searchParams.get('destination_ip') || undefined,
      since: windowMinutes === null ? undefined : windowStart(windowMinutes),
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [searchParams],
  )

  const { events, hasNextPage, liveState, lastSuccessfulRefreshAt, isRefreshing, refresh } = useThreatHuntQuery(page, filters)

  function applyFilters(next: HuntFilters, nextWindowMinutes: number | null) {
    const params = new URLSearchParams()
    if (next.event_type) params.set('event_type', next.event_type)
    if (next.source) params.set('source', next.source)
    if (next.hostname) params.set('hostname', next.hostname)
    if (next.username) params.set('username', next.username)
    if (next.source_ip) params.set('source_ip', next.source_ip)
    if (next.destination_ip) params.set('destination_ip', next.destination_ip)
    params.set('window', nextWindowMinutes === null ? 'all' : String(nextWindowMinutes))
    setSearchParams(params)
  }

  function removeFilter(key: keyof HuntFilters) {
    const params = new URLSearchParams(searchParams)
    params.delete(key)
    setSearchParams(params)
  }

  function pivot(filterKey: keyof HuntFilters, value: string) {
    const params = new URLSearchParams(searchParams)
    params.set(filterKey, value)
    params.set('page', '1')
    setSearchParams(params)
  }

  function goToPage(nextPage: number) {
    const params = new URLSearchParams(searchParams)
    params.set('page', String(nextPage))
    setSearchParams(params)
  }

  const hasFilters = Boolean(
    filters.event_type || filters.source || filters.hostname || filters.username || filters.source_ip || filters.destination_ip,
  )

  return (
    <div className="mx-auto max-w-[1600px] px-6 py-6">
      <PageHeader
        title="Threat Hunting"
        description="Explore recent security telemetry and pivot into an investigation, using the same real events AMNIX already ingests."
        action={
          <div className="flex items-center gap-3">
            <LiveIndicator state={liveState} lastSuccessfulRefreshAt={lastSuccessfulRefreshAt} />
            <RefreshButton onRefresh={refresh} isRefreshing={isRefreshing} />
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_380px]">
        <Card className="overflow-hidden">
          <HuntFilterPanel filters={filters} windowMinutes={windowMinutes} onApply={applyFilters} onClear={() => setSearchParams({})} />
          <HuntContextBar filters={filters} windowMinutes={windowMinutes} eventCount={events.length} hasNextPage={hasNextPage} onRemoveFilter={removeFilter} />

          {liveState === 'error' ? (
            <ErrorState title="Unable to run this hunt" onRetry={refresh} />
          ) : liveState === 'loading' ? (
            <div>
              {Array.from({ length: 8 }).map((_, i) => (
                <SkeletonRow key={i} />
              ))}
            </div>
          ) : events.length === 0 ? (
            <EmptyState
              icon={Crosshair}
              title={hasFilters ? 'No events match this hunt.' : 'No events in this time window.'}
              description={hasFilters ? 'Try clearing or widening the current filters.' : 'Widen the time window, or wait for more telemetry.'}
            />
          ) : (
            <>
              <HuntResultsTable events={events} focusedEventId={focusedEvent?.id} onSelectEvent={setFocusedEvent} />
              <Pagination page={page} hasNext={hasNextPage} onPrevious={() => goToPage(page - 1)} onNext={() => goToPage(page + 1)} />
            </>
          )}
        </Card>

        <EventInspectorPanel event={focusedEvent} onPivot={pivot} />
      </div>
    </div>
  )
}
