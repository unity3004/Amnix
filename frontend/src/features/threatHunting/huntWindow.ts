import { OBSERVATION_WINDOW_OPTIONS, windowStart, type ObservationWindowOption } from '@/lib/observationWindow'

/**
 * Reuses Step 12I's own OBSERVATION_WINDOW_OPTIONS/windowStart verbatim
 * (never redefined) as the base, then adds two hunting-specific options
 * on top -- a live operational dashboard has no reason to look back 7
 * days, but a hunt genuinely does.
 *
 * Both additions are honestly safe under GET /events' real contract
 * (confirmed by reading backend/app/repositories/security_event.py):
 * `since`/`until` only narrow WHERE event_timestamp falls, and the
 * response is ALWAYS capped by `limit` (1-200) regardless of how wide
 * the time range is -- a 7-day or unbounded window can never return
 * more rows than a 15-minute one, it can only change WHICH `limit` rows
 * (the newest, per the existing event_timestamp index) come back.
 * "All time" means omitting `since` entirely, the same "no time
 * constraint" pattern AlertsFilterToolbar's own `hours: null` option
 * already uses elsewhere in AMNIX.
 */
export const HUNT_WINDOW_OPTIONS: ObservationWindowOption[] = [
  ...OBSERVATION_WINDOW_OPTIONS,
  { label: 'Last 7 days', minutes: 7 * 24 * 60 },
]

export const HUNT_ALL_TIME_LABEL = 'All time'

export { windowStart }
