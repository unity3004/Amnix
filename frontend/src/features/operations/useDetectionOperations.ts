import { useMemo } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { listAlerts } from '@/services/alertsService'
import { LIVE_REFRESH_INTERVAL_MS, type LiveQueryState } from '@/lib/liveRefresh'
import { windowStart } from '@/lib/observationWindow'
import type { AlertsFilters } from '@/features/alerts/types'

export const OPERATIONS_PAGE_SIZE = 100

/** Step 12J: the one centralized data hook for the Detection
 * Operations page. Exactly one real backend request per load/refresh/
 * window-or-filter change -- GET /alerts, already existing, bounded by
 * the analyst-selected observation window's `since` filter (Step 12B's
 * own supported contract) plus whatever status/severity/rule_id
 * filters are active. Never a per-rule, per-alert, investigation, or
 * Copilot request.
 *
 * Deliberately NOT built on top of useAlertsListQuery: that hook's
 * queryFn closes over a `filters` object captured at render time, so
 * reusing it directly for a live-polled "observation window" would
 * silently freeze `since` between window changes -- the exact
 * staleness bug Step 12I found and fixed by computing `since` fresh
 * inside queryFn on every fetch (see lib/observationWindow.ts). This
 * hook follows that same safe pattern instead, while still reusing the
 * identical underlying listAlerts() call, LIVE_REFRESH_INTERVAL_MS, and
 * LiveQueryState conventions -- no second query architecture, just no
 * unsafe closure over a stale `since`.
 */
export function useDetectionOperations(windowMinutes: number, filters: Omit<AlertsFilters, 'since' | 'until'>) {
  const query = useQuery({
    queryKey: ['operations', 'alerts', windowMinutes, filters],
    queryFn: () => listAlerts({ since: windowStart(windowMinutes), limit: OPERATIONS_PAGE_SIZE, ...filters }),
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
    alerts: query.data?.items ?? [],
    hitPageLimit: (query.data?.items.length ?? 0) === OPERATIONS_PAGE_SIZE,
    liveState,
    lastSuccessfulRefreshAt,
    isRefreshing: query.isFetching,
    refresh: () => query.refetch(),
  }
}
