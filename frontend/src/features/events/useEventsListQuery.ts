import { useMemo } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { listEvents } from '@/services/eventsService'
import { LIVE_REFRESH_INTERVAL_MS, type LiveQueryState } from '@/lib/liveRefresh'
import type { EventsFilters } from './types'

export const EVENTS_PAGE_SIZE = 25

export function useEventsListQuery(page: number, filters: EventsFilters) {
  const offset = (page - 1) * EVENTS_PAGE_SIZE

  const query = useQuery({
    queryKey: ['events-list', page, filters],
    queryFn: () => listEvents({ limit: EVENTS_PAGE_SIZE, offset, ...filters }),
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
    hasNextPage: (query.data?.items.length ?? 0) === EVENTS_PAGE_SIZE,
    liveState,
    lastSuccessfulRefreshAt,
    isRefreshing: query.isFetching,
    refresh: () => query.refetch(),
  }
}
