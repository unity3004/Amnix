import { useMemo } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { listCases } from '@/services/casesService'
import { LIVE_REFRESH_INTERVAL_MS, type LiveQueryState } from '@/lib/liveRefresh'
import type { CasesFilters } from './types'

export const CASES_PAGE_SIZE = 25

export function useCasesListQuery(page: number, filters: CasesFilters) {
  const offset = (page - 1) * CASES_PAGE_SIZE

  const query = useQuery({
    queryKey: ['cases-list', page, filters],
    queryFn: () => listCases({ limit: CASES_PAGE_SIZE, offset, ...filters }),
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
    cases: query.data?.items ?? [],
    hasNextPage: (query.data?.items.length ?? 0) === CASES_PAGE_SIZE,
    liveState,
    lastSuccessfulRefreshAt,
    isRefreshing: query.isFetching,
    refresh: () => query.refetch(),
  }
}
