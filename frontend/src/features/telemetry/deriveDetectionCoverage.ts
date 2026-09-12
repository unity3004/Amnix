import { DETECTION_RULES, type DetectionRuleDefinition } from '@/features/rules/ruleRegistry'
import type { AlertRead, SecurityEventRead } from '@/types/api'

/** DERIVED ANALYST VIEW combining two real, already-fetched sources
 * (the bounded GET /events and GET /alerts pages) with one STATIC
 * DETECTION DEFINITION source (the Step 12H rule registry -- reused
 * as-is, never a second competing registry). Every status below is an
 * observation about THIS bounded window, never a percentage, score, or
 * pass/fail verdict on the rule itself -- see the module docstring in
 * ruleRegistry.ts for why threshold/window values are handled the same
 * way (real defaults, never asserted as guaranteed facts beyond what
 * was actually observed).
 */
export interface RuleCoverage {
  rule: DetectionRuleDefinition
  telemetryObserved: boolean
  /** Which of the rule's required event types were actually observed;
   * empty when none were. */
  observedEventTypes: string[]
  /** Which required event types were NOT observed in this window. */
  missingEventTypes: string[]
  recentAlertCount: number
  hasRecentAlertActivity: boolean
}

export function deriveDetectionCoverage(events: SecurityEventRead[], alerts: AlertRead[]): RuleCoverage[] {
  const observedEventTypeSet = new Set(events.map((e) => e.event_type))
  const alertCountByRuleId = new Map<string, number>()
  for (const alert of alerts) {
    alertCountByRuleId.set(alert.rule_id, (alertCountByRuleId.get(alert.rule_id) ?? 0) + 1)
  }

  return DETECTION_RULES.map((rule) => {
    const observedEventTypes = rule.eventTypes.filter((t) => observedEventTypeSet.has(t))
    const missingEventTypes = rule.eventTypes.filter((t) => !observedEventTypeSet.has(t))
    const recentAlertCount = alertCountByRuleId.get(rule.ruleId) ?? 0
    return {
      rule,
      telemetryObserved: observedEventTypes.length > 0,
      observedEventTypes,
      missingEventTypes,
      recentAlertCount,
      hasRecentAlertActivity: recentAlertCount > 0,
    }
  })
}

export interface TelemetryToRuleMapping {
  eventType: string
  dependentRules: DetectionRuleDefinition[]
}

/** The inverse view: for each OBSERVED event type, which real rules
 * declare a dependency on it -- and which observed event types have no
 * rule depending on them at all (informational, not a failure).
 */
export function deriveTelemetryToRuleMapping(events: SecurityEventRead[]): TelemetryToRuleMapping[] {
  const observedEventTypes = Array.from(new Set(events.map((e) => e.event_type))).sort()
  return observedEventTypes.map((eventType) => ({
    eventType,
    dependentRules: DETECTION_RULES.filter((rule) => rule.eventTypes.includes(eventType)),
  }))
}

export type VisibilityGapKind = 'missing-telemetry' | 'unmapped-event-type' | 'no-recent-activity'

export interface VisibilityGap {
  kind: VisibilityGapKind
  message: string
}

/** Conservative, neutrally-worded observations only -- never a
 * "broken"/"failed" claim. See the module-level guidance this mirrors
 * in the Step 12I brief: absence of recent data is an observation, not
 * proof of a pipeline failure.
 */
export function deriveVisibilityGaps(coverage: RuleCoverage[], telemetryToRule: TelemetryToRuleMapping[]): VisibilityGap[] {
  const gaps: VisibilityGap[] = []

  for (const entry of coverage) {
    for (const eventType of entry.missingEventTypes) {
      gaps.push({
        kind: 'missing-telemetry',
        message: `Potential visibility gap: "${entry.rule.name}" depends on "${eventType}", which was not recently observed in the selected window.`,
      })
    }
  }

  for (const mapping of telemetryToRule) {
    if (mapping.dependentRules.length === 0) {
      gaps.push({
        kind: 'unmapped-event-type',
        message: `Telemetry observed for "${mapping.eventType}" with no associated detection rule in the current registry.`,
      })
    }
  }

  for (const entry of coverage) {
    if (entry.telemetryObserved && !entry.hasRecentAlertActivity) {
      gaps.push({
        kind: 'no-recent-activity',
        message: `"${entry.rule.name}" has telemetry dependency observed, but no recent detection activity in the selected window.`,
      })
    }
  }

  return gaps
}
