/** The one polling interval every live AMNIX view shares (dashboard,
 * alerts, events) -- see each page's own useQuery({ refetchInterval })
 * usage. A single shared constant so "the same live state/polling
 * language established by the dashboard" (Step 12D brief §19) is
 * enforced by construction, not by convention alone.
 */
export const LIVE_REFRESH_INTERVAL_MS = 15_000

/** Shared live-state vocabulary for any polled list/detail query
 * (dashboard, alerts, events). See useDashboardData.ts's own docstring
 * for the full reasoning behind these four states.
 */
export type LiveQueryState = 'loading' | 'live' | 'degraded' | 'error'
