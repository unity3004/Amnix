import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { listAlerts } from '@/services/alertsService'
import { listEvents } from '@/services/eventsService'
import { getHealth } from '@/services/healthService'
import type { LiveQueryState } from '@/lib/liveRefresh'

/** The one, centralized refresh interval every dashboard panel shares
 * -- no panel below this hook ever calls a service function itself
 * (brief §4/§6: "ONE centralized dashboard refresh cycle", "do not
 * create one timer per panel"). React Query's own `refetchInterval`
 * mechanism is used instead of a hand-rolled setInterval: it is
 * already tied to the observing component's lifecycle (cleaned up
 * automatically on unmount), already de-duplicates overlapping
 * requests (calling refetch() while a fetch is in flight reuses the
 * same in-flight promise rather than firing a second request), and
 * already exposes per-query dataUpdatedAt/isError/isFetching state --
 * exactly what the LIVE/DEGRADED/LOADING state model below needs,
 * without reimplementing any of it by hand.
 */
export const DASHBOARD_REFRESH_INTERVAL_MS = 15_000
const DASHBOARD_PAGE_SIZE = 50

/** @deprecated use LiveQueryState from '@/lib/liveRefresh' -- kept as
 * an alias so this hook's existing public return type doesn't change.
 */
export type DashboardLiveState = LiveQueryState

export function useDashboardData() {
  const alertsQuery = useQuery({
    queryKey: ['dashboard', 'alerts'],
    queryFn: () => listAlerts({ limit: DASHBOARD_PAGE_SIZE }),
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS,
    refetchIntervalInBackground: false,
  })

  const eventsQuery = useQuery({
    queryKey: ['dashboard', 'events'],
    queryFn: () => listEvents({ limit: DASHBOARD_PAGE_SIZE }),
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS,
    refetchIntervalInBackground: false,
  })

  const healthQuery = useQuery({
    queryKey: ['dashboard', 'health'],
    queryFn: getHealth,
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS,
    refetchIntervalInBackground: false,
    retry: false,
  })

  // React Query keeps the previous `data` in place across a failed
  // background refetch by default (v5 behavior) -- so `isError` always
  // reflects the LATEST attempt while `data`/`dataUpdatedAt` still
  // reflect the last SUCCESSFUL one. That is exactly what distinguishes
  // "degraded" (stale-but-usable data) from "error" (never got any).
  const lastSuccessfulRefreshAt = useMemo(() => {
    const timestamps = [alertsQuery.dataUpdatedAt, eventsQuery.dataUpdatedAt].filter((t) => t > 0)
    return timestamps.length > 0 ? new Date(Math.max(...timestamps)) : null
  }, [alertsQuery.dataUpdatedAt, eventsQuery.dataUpdatedAt])

  const liveState: DashboardLiveState = useMemo(() => {
    const stillLoadingInitial =
      (alertsQuery.isPending && !alertsQuery.data) || (eventsQuery.isPending && !eventsQuery.data)
    if (stillLoadingInitial) return 'loading'

    const hasAnyData = Boolean(alertsQuery.data) || Boolean(eventsQuery.data)
    const eitherFailed = alertsQuery.isError || eventsQuery.isError

    if (!hasAnyData && eitherFailed) return 'error'
    if (eitherFailed) return 'degraded'
    return 'live'
  }, [alertsQuery.isPending, alertsQuery.data, alertsQuery.isError, eventsQuery.isPending, eventsQuery.data, eventsQuery.isError])

  async function refreshAll() {
    // queryClient.invalidateQueries + refetch would also work, but
    // calling each query's own refetch() is simplest and, per React
    // Query's own dedup behavior, is already a no-op if a refresh from
    // the polling interval is already in flight.
    await Promise.allSettled([alertsQuery.refetch(), eventsQuery.refetch(), healthQuery.refetch()])
  }

  return {
    alerts: alertsQuery.data?.items ?? [],
    alertsError: alertsQuery.isError,
    alertsLoading: alertsQuery.isPending,
    events: eventsQuery.data?.items ?? [],
    eventsError: eventsQuery.isError,
    eventsLoading: eventsQuery.isPending,
    health: healthQuery.data ?? null,
    healthError: healthQuery.isError,
    liveState,
    lastSuccessfulRefreshAt,
    isRefreshing: alertsQuery.isFetching || eventsQuery.isFetching || healthQuery.isFetching,
    refreshAll,
  }
}
