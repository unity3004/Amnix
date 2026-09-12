import type { RuleCoverage } from '@/features/telemetry/deriveDetectionCoverage'
import type { DetectionRuleDefinition } from '@/features/rules/ruleRegistry'
import { getMitreTechniquesForRule, type MitreTechnique } from '@/features/dashboard/mitreRegistry'
import type { AlertRead } from '@/types/api'

/** Step 12O: DERIVED ANALYST VIEWS built entirely from Step 12I's
 * deriveDetectionCoverage() (unmodified) plus the real, already-fetched
 * bounded GET /alerts page -- no new request, no second registry.
 *
 * Every value here is an OBSERVATION about this bounded window, never a
 * verdict on the rule. Presence of telemetry, alerts, evidence, or a
 * MITRE mapping does not establish that a rule is effective, accurate,
 * or that any specific alert is a true positive -- see this file's
 * describeObservation() for the neutral vocabulary this constraint
 * requires throughout the Detection Health page.
 */

export interface RuleEvidenceObservability {
  alertsReturned: number
  evidenceBearingAlerts: number
  supportingEventAlerts: number
}

/** Per-rule evidence presence counts over the real, bounded GET /alerts
 * page already fetched. Presence only -- never a percentage, never a
 * "quality" or "confidence" figure (see the Step 12O report's Evidence
 * Observability section for why that distinction matters).
 */
export function deriveRuleEvidenceObservability(alerts: AlertRead[]): Map<string, RuleEvidenceObservability> {
  const byRule = new Map<string, RuleEvidenceObservability>()
  for (const alert of alerts) {
    const entry = byRule.get(alert.rule_id) ?? { alertsReturned: 0, evidenceBearingAlerts: 0, supportingEventAlerts: 0 }
    entry.alertsReturned += 1
    if (Object.keys(alert.evidence).length > 0) entry.evidenceBearingAlerts += 1
    if (alert.source_event_ids.length > 0) entry.supportingEventAlerts += 1
    byRule.set(alert.rule_id, entry)
  }
  return byRule
}

/** The four neutral observation states this step's brief explicitly
 * enumerates -- deliberately never "working"/"broken"/"effective"/
 * "ineffective". The fourth case (alert activity present without this
 * window's telemetry sample containing the dependent event type) is a
 * real, honest possibility: GET /events and GET /alerts are two
 * independently bounded/paginated queries over the same window, so an
 * event supporting an alert may simply not have been included in this
 * particular bounded events page.
 */
export function describeObservation(telemetryObserved: boolean, hasRecentAlertActivity: boolean): string {
  if (telemetryObserved && hasRecentAlertActivity) return 'Telemetry observed; recent alert activity observed.'
  if (telemetryObserved && !hasRecentAlertActivity) return 'Telemetry observed; no recent alert activity returned.'
  if (!telemetryObserved && hasRecentAlertActivity) {
    return 'Recent alert activity observed; dependent telemetry not returned in this bounded view.'
  }
  return 'No dependent telemetry observed in this view.'
}

export interface RuleObservabilityRow {
  rule: DetectionRuleDefinition
  telemetryObserved: boolean
  observedEventTypes: string[]
  missingEventTypes: string[]
  recentAlertCount: number
  evidence: RuleEvidenceObservability
  mitreTechniques: MitreTechnique[]
  observation: string
}

/** Combines Step 12I's per-rule telemetry/alert coverage with this
 * step's new evidence-observability counts and the existing MITRE
 * registry lookup -- one row per real, application-controlled
 * registered rule (see deriveUnknownRuleActivity() for rule_ids that
 * appear in alerts but aren't in the registry, handled separately so
 * this function never has to fabricate a name/event-type/MITRE entry
 * for them).
 */
export function deriveRuleObservability(coverage: RuleCoverage[], alerts: AlertRead[]): RuleObservabilityRow[] {
  const evidenceByRule = deriveRuleEvidenceObservability(alerts)
  return coverage.map((entry) => ({
    rule: entry.rule,
    telemetryObserved: entry.telemetryObserved,
    observedEventTypes: entry.observedEventTypes,
    missingEventTypes: entry.missingEventTypes,
    recentAlertCount: entry.recentAlertCount,
    evidence: evidenceByRule.get(entry.rule.ruleId) ?? { alertsReturned: 0, evidenceBearingAlerts: 0, supportingEventAlerts: 0 },
    mitreTechniques: getMitreTechniquesForRule(entry.rule.ruleId),
    observation: describeObservation(entry.telemetryObserved, entry.recentAlertCount > 0),
  }))
}

export interface UnknownRuleActivity {
  ruleId: string
  recentAlertCount: number
}

/** rule_ids present on real, returned alerts but absent from the
 * static frontend registry -- handled safely: raw rule_id and an alert
 * count only, never a fabricated name, event type, or MITRE mapping.
 */
export function deriveUnknownRuleActivity(alerts: AlertRead[], knownRuleIds: Set<string>): UnknownRuleActivity[] {
  const counts = new Map<string, number>()
  for (const alert of alerts) {
    if (knownRuleIds.has(alert.rule_id)) continue
    counts.set(alert.rule_id, (counts.get(alert.rule_id) ?? 0) + 1)
  }
  return Array.from(counts.entries())
    .map(([ruleId, recentAlertCount]) => ({ ruleId, recentAlertCount }))
    .sort((a, b) => b.recentAlertCount - a.recentAlertCount)
}
