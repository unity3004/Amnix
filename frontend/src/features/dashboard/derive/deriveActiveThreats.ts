import type { AlertRead } from '@/types/api'
import type { ActiveThreatSummary } from '../types'
import { lookupMitreTechnique } from '../mitreRegistry'

/** Maps real AlertRead rows (already newest-first from the backend --
 * see AlertRepository.list_recent()) into the Active Threats panel's
 * display shape. `mitre` is null, never guessed, when `rule_id` has no
 * registry entry.
 */
export function deriveActiveThreats(alerts: AlertRead[]): ActiveThreatSummary[] {
  return alerts.map((alert) => ({
    id: alert.id,
    title: alert.title,
    ruleId: alert.rule_id,
    severity: alert.severity,
    status: alert.status,
    firstSeen: alert.first_seen,
    lastSeen: alert.last_seen,
    mitre: lookupMitreTechnique(alert.rule_id),
  }))
}
