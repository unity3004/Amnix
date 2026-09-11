import { useMemo } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { listAlerts } from '@/services/alertsService'
import { LIVE_REFRESH_INTERVAL_MS, type LiveQueryState } from '@/lib/liveRefresh'
import type { AlertsFilters } from './types'

export const ALERTS_PAGE_SIZE = 25

export function useAlertsListQuery(page: number, filters: AlertsFilters) {
  const offset = (page - 1) * ALERTS_PAGE_SIZE

  const query = useQuery({
    queryKey: ['alerts-list', page, filters],
    queryFn: () => listAlerts({ limit: ALERTS_PAGE_SIZE, offset, ...filters }),
    refetchInterval: LIVE_REFRESH_INTERVAL_MS,
    refetchIntervalInBackground: false,
    // Keeps the previous page's rows visible while a new page/filter
    // combination loads, instead of flashing back to a loading
    // skeleton on every filter change -- a UX nicety, not a data
    // integrity concern (the query key still fully identifies which
    // exact request produced the currently-shown data).
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
    alerts: query.data?.items ?? [],
    hasNextPage: (query.data?.items.length ?? 0) === ALERTS_PAGE_SIZE,
    liveState,
    lastSuccessfulRefreshAt,
    isRefreshing: query.isFetching,
    refresh: () => query.refetch(),
  }
}
