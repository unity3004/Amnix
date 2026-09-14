import { useMemo } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { listEvents } from '@/services/eventsService'
import { LIVE_REFRESH_INTERVAL_MS, type LiveQueryState } from '@/lib/liveRefresh'
import type { HuntFilters } from './types'

export const HUNT_PAGE_SIZE = 50

/** ONE GET /events request for the current hunt's result set -- reuses
 * the exact same listEvents() service call EventsPage already uses,
 * just over the richer Step 12X filter surface. No per-event fetch is
 * triggered by this hook; the inline event inspector renders directly
 * from whichever row the analyst already has in `events` (GET /events
 * already returns the full SecurityEventRead per row, identical shape
 * to GET /events/{id} -- see EventEvidenceFields' own docstring).
 */
export function useThreatHuntQuery(page: number, filters: HuntFilters) {
  const offset = (page - 1) * HUNT_PAGE_SIZE

  const query = useQuery({
    queryKey: ['threat-hunt', page, filters],
    queryFn: () => listEvents({ limit: HUNT_PAGE_SIZE, offset, ...filters }),
    refetchInterval: LIVE_REFRESH_INTERVAL_MS,
    refetchIntervalInBackground: false,
    placeholderData: keepPreviousData,
  })

  const liveState: LiveQueryState = useMemo(() => {
    if (query.isPending && !query.data) return 'loading'
    if (query.isError && !query.data) return 'error'
    if (query.isError) return 'degraded'
    return 'live'
  }, [query.isPending, query.isError, query.data])

  const lastSuccessfulRefreshAt = query.dataUpdatedAt > 0 ? new Date(query.dataUpdatedAt) : null

  return {
    events: query.data?.items ?? [],
    hasNextPage: (query.data?.items.length ?? 0) === HUNT_PAGE_SIZE,
    liveState,
    lastSuccessfulRefreshAt,
    isRefreshing: query.isFetching,
    refresh: () => query.refetch(),
  }
}
