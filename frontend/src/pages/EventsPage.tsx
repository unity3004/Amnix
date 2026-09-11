import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Activity } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { SkeletonRow } from '@/components/ui/Skeleton'
import { Pagination } from '@/components/ui/Pagination'
import { LiveIndicator } from '@/components/live/LiveIndicator'
import { RefreshButton } from '@/components/live/RefreshButton'
import { EventsFilterToolbar } from '@/features/events/components/EventsFilterToolbar'
import { EventRow } from '@/features/events/components/EventRow'
import { useEventsListQuery } from '@/features/events/useEventsListQuery'
import type { EventsFilters } from '@/features/events/types'

const COLUMN_HEADERS = [
  { label: 'Timestamp', className: '' },
  { label: 'Event Type', className: '' },
  { label: 'Source', className: 'hidden sm:table-cell' },
  { label: 'Hostname', className: 'hidden md:table-cell' },
  { label: 'Username', className: 'hidden md:table-cell' },
  { label: 'Source IP', className: 'hidden lg:table-cell' },
]

export function EventsPage() {
  const [searchParams, setSearchParams] = useSearchParams()

  const page = Math.max(1, Number(searchParams.get('page') ?? '1') || 1)
  const filters: EventsFilters = useMemo(
    () => ({
      event_type: searchParams.get('event_type') || undefined,
      source: searchParams.get('source') || undefined,
      since: searchParams.get('since') || undefined,
      until: searchParams.get('until') || undefined,
    }),
    [searchParams],
  )

  const { events, hasNextPage, liveState, lastSuccessfulRefreshAt, isRefreshing, refresh } = useEventsListQuery(page, filters)

  function applyFilters(next: EventsFilters) {
    const params = new URLSearchParams()
    if (next.event_type) params.set('event_type', next.event_type)
    if (next.source) params.set('source', next.source)
    if (next.since) params.set('since', next.since)
    if (next.until) params.set('until', next.until)
    setSearchParams(params)
  }

  function goToPage(nextPage: number) {
    const params = new URLSearchParams(searchParams)
    params.set('page', String(nextPage))
    setSearchParams(params)
  }

  const hasFilters = Boolean(filters.event_type || filters.source || filters.since || filters.until)

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader
        title="Events"
        description="Security telemetry received by AMNIX"
        action={
          <div className="flex items-center gap-3">
            <LiveIndicator state={liveState} lastSuccessfulRefreshAt={lastSuccessfulRefreshAt} />
            <RefreshButton onRefresh={refresh} isRefreshing={isRefreshing} />
          </div>
        }
      />

      <Card className="overflow-hidden">
        <EventsFilterToolbar filters={filters} onApply={applyFilters} onClear={() => setSearchParams({})} />

        {liveState === 'error' ? (
          <ErrorState title="Unable to retrieve telemetry" onRetry={refresh} />
        ) : liveState === 'loading' ? (
          <div>
            {Array.from({ length: 8 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        ) : events.length === 0 ? (
          <EmptyState
            icon={Activity}
            title={hasFilters ? 'No events found' : 'No security events'}
            description={hasFilters ? 'No telemetry matches the current filters.' : 'Waiting for telemetry.'}
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse">
                <thead>
                  <tr className="border-b border-border text-left">
                    {COLUMN_HEADERS.map((col) => (
                      <th key={col.label} className={`px-5 py-2 text-[11px] font-medium uppercase tracking-wide text-fg-subtle first:px-5 ${col.className}`}>
                        {col.label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => (
                    <EventRow key={event.id} event={event} />
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} hasNext={hasNextPage} onPrevious={() => goToPage(page - 1)} onNext={() => goToPage(page + 1)} />
          </>
        )}
      </Card>
    </div>
  )
}
