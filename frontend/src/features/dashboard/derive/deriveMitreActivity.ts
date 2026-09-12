import type { AlertRead } from '@/types/api'
import type { MitreActivityEntry } from '../types'
import { lookupMitreTechnique } from '../mitreRegistry'

/** Aggregates Alert.rule_id counts from the CURRENTLY RETRIEVED bounded
 * GET /alerts page against the real, static MITRE registry
 * (mitreRegistry.ts) -- never a global total across the whole
 * database, and never a fabricated technique mapping: a rule_id with
 * no registry entry contributes nothing (see MitreActivityPanel for
 * how "based on recent alerts" is surfaced to the analyst so this
 * scope limitation is never presented as a complete picture).
 * Sorted by count, descending.
 */
export function deriveMitreActivity(alerts: AlertRead[]): MitreActivityEntry[] {
  const counts = new Map<string, number>()
  for (const alert of alerts) {
    counts.set(alert.rule_id, (counts.get(alert.rule_id) ?? 0) + 1)
  }

  const entries: MitreActivityEntry[] = []
  for (const [ruleId, count] of counts) {
    const technique = lookupMitreTechnique(ruleId)
    if (!technique) continue
    entries.push({
      techniqueId: technique.techniqueId,
      name: technique.name,
      tactic: technique.tactic,
      detectionCount: count,
      sourceRuleId: ruleId,
    })
  }

  return entries.sort((a, b) => b.detectionCount - a.detectionCount)
}
