import { DEMO_OVERVIEW } from './demoData'
import type { DashboardOverview } from './types'

/**
 * The ONE function the dashboard page calls for its data. Today this
 * resolves isolated frontend demo data (see demoData.ts for exactly
 * why — no backend list endpoint exists yet for alerts/events). Once
 * AMNIX exposes a list/aggregate endpoint, this is the only place that
 * needs to change: swap the body for a real `apiRequest<...>(...)`
 * call that returns the same `DashboardOverview` shape, and every
 * component downstream (MetricCard, ThreatActivityChart,
 * RecentAlertsPanel, ...) keeps working unmodified.
 *
 * The artificial delay below exists only so the dashboard's loading
 * skeleton is honestly exercised during development — it is not a
 * simulation of network latency and must be removed the moment this
 * function starts making a real request (a real `fetch` will already
 * be asynchronous).
 */
export async function getDashboardOverview(): Promise<DashboardOverview> {
  await new Promise((resolve) => setTimeout(resolve, 450))
  return DEMO_OVERVIEW
}
