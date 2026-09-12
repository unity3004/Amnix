import type { AlertRead } from '@/types/api'
import type { ThreatPulseState } from '../types'

/** How far back "recent" looks for the pulse calculation. A deliberate,
 * documented constant -- not tunable by any UI control, not derived
 * from a backend value that doesn't exist.
 */
export const THREAT_PULSE_WINDOW_MS = 15 * 60 * 1000 // 15 minutes

/**
 * Deterministic ACTIVITY STATE (never a numeric "threat score") derived
 * from the severities of alerts whose `first_seen` falls within the
 * last THREAT_PULSE_WINDOW_MS, taken from the currently-retrieved
 * bounded GET /alerts page:
 *
 *   any CRITICAL in the window  -> 'critical'
 *   else any HIGH in the window -> 'active'
 *   else any MEDIUM in the window -> 'elevated'
 *   else any alert at all in the window (i.e. only LOW) -> 'guarded'
 *   else (nothing recent)       -> 'quiet'
 *
 * This is intentionally the simplest rule that uses only real,
 * already-available Alert.severity/.first_seen values -- no weighting,
 * no decay curve, no fabricated scoring model.
 */
export function deriveThreatPulse(alerts: AlertRead[], now: Date = new Date()): ThreatPulseState {
  const windowStart = now.getTime() - THREAT_PULSE_WINDOW_MS
  const recent = alerts.filter((alert) => new Date(alert.first_seen).getTime() >= windowStart)

  if (recent.some((a) => a.severity === 'critical')) return 'critical'
  if (recent.some((a) => a.severity === 'high')) return 'active'
  if (recent.some((a) => a.severity === 'medium')) return 'elevated'
  if (recent.length > 0) return 'guarded'
  return 'quiet'
}
