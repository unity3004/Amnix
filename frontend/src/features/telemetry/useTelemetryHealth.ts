import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { listEvents } from '@/services/eventsService'
import { listAlerts } from '@/services/alertsService'
import { LIVE_REFRESH_INTERVAL_MS, type LiveQueryState } from '@/lib/liveRefresh'

function windowStart(windowMinutes: number): string {
  return new Date(Date.now() - windowMinutes * 60_000).toISOString()
}

/** Step 12I: the one centralized data hook for the Telemetry &
 * Detection Coverage page. Exactly two real backend requests per
 * load/refresh cycle -- GET /events and GET /alerts, both already
 * existing, both bounded by the analyst-selected observation window's
 * `since` filter (Step 12B's own supported contract) -- never a
 * per-rule or per-event-type request. Reuses the same React Query
 * `refetchInterval` + LiveQueryState pattern already established by
 * useDashboardData.ts / useAlertsListQuery.ts, with its own query keys
 * so it neither shares nor duplicates those hooks' polling.
 */
export const TELEMETRY_PAGE_SIZE = 100

export interface TelemetryWindowOption {
  label: string
  minutes: number
}

export const TELEMETRY_WINDOW_OPTIONS: TelemetryWindowOption[] = [
  { label: 'Last 15 minutes', minutes: 15 },
  { label: 'Last hour', minutes: 60 },
  { label: 'Last 24 hours', minutes: 24 * 60 },
]

export function useTelemetryHealth(windowMinutes: number) {
  // `since` is recomputed from the real current time on every fetch --
  // including background polling refetches -- by calling windowStart()
  // inside each queryFn, not by memoizing it against `windowMinutes`
  // alone. Memoizing it would freeze `since` at whatever "now" was when
  // the window was last changed, silently widening the effective
  // window (e.g. "last 15 minutes" slowly becoming 20, 25... minutes)
  // for as long as the analyst leaves the selector untouched.
  const eventsQuery = useQuery({
    queryKey: ['telemetry', 'events', windowMinutes],
    queryFn: () => listEvents({ since: windowStart(windowMinutes), limit: TELEMETRY_PAGE_SIZE }),
    refetchInterval: LIVE_REFRESH_INTERVAL_MS,
    refetchIntervalInBackground: false,
  })

  const alertsQuery = useQuery({
    queryKey: ['telemetry', 'alerts', windowMinutes],
    queryFn: () => listAlerts({ since: windowStart(windowMinutes), limit: TELEMETRY_PAGE_SIZE }),
    refetchInterval: LIVE_REFRESH_INTERVAL_MS,
    refetchIntervalInBackground: false,
  })

  const eventsLiveState: LiveQueryState = eventsQuery.isPending
    ? 'loading'
    : eventsQuery.isError && !eventsQuery.data
      ? 'error'
      : eventsQuery.isError
        ? 'degraded'
        : 'live'

  const alertsLiveState: LiveQueryState = alertsQuery.isPending
    ? 'loading'
    : alertsQuery.isError && !alertsQuery.data
      ? 'error'
      : alertsQuery.isError
        ? 'degraded'
        : 'live'

  const lastSuccessfulRefreshAt = useMemo(() => {
    const timestamps = [eventsQuery.dataUpdatedAt, alertsQuery.dataUpdatedAt].filter((t) => t > 0)
    return timestamps.length > 0 ? new Date(Math.max(...timestamps)) : null
  }, [eventsQuery.dataUpdatedAt, alertsQuery.dataUpdatedAt])

  async function refresh() {
    await Promise.allSettled([eventsQuery.refetch(), alertsQuery.refetch()])
  }

  return {
    events: eventsQuery.data?.items ?? [],
    eventsLiveState,
    eventsHitPageLimit: (eventsQuery.data?.items.length ?? 0) === TELEMETRY_PAGE_SIZE,
    alerts: alertsQuery.data?.items ?? [],
    alertsLiveState,
    alertsHitPageLimit: (alertsQuery.data?.items.length ?? 0) === TELEMETRY_PAGE_SIZE,
    lastSuccessfulRefreshAt,
    isRefreshing: eventsQuery.isFetching || alertsQuery.isFetching,
    refresh,
  }
}
