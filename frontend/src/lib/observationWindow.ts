/** Shared observation-window model, established in Step 12I (Telemetry
 * & Detection Coverage) and reused as-is by Step 12J (Detection
 * Operations) rather than being redefined a second time.
 *
 * `windowStart` must be called fresh inside a query's own `queryFn` on
 * every fetch (including background polling refetches) -- never
 * memoized against `windowMinutes` alone. Memoizing it would freeze
 * `since` at whatever "now" was when the window was last changed,
 * silently widening the effective window (e.g. "last 15 minutes"
 * slowly becoming 20, 25... minutes) for as long as the analyst leaves
 * the selector untouched. This exact bug was found and fixed in Step
 * 12I; extracting the helper here keeps the fix shared instead of
 * something a future page could reintroduce by copy-pasting the old
 * (broken) pattern.
 */

export interface ObservationWindowOption {
  label: string
  minutes: number
}

export const OBSERVATION_WINDOW_OPTIONS: ObservationWindowOption[] = [
  { label: 'Last 15 minutes', minutes: 15 },
  { label: 'Last hour', minutes: 60 },
  { label: 'Last 24 hours', minutes: 24 * 60 },
]

export function windowStart(windowMinutes: number): string {
  return new Date(Date.now() - windowMinutes * 60_000).toISOString()
}
