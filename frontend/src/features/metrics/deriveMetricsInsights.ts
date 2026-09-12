import { getMitreTechniquesForRule } from '@/features/dashboard/mitreRegistry'
import type { AlertRead, SecurityEventRead } from '@/types/api'

export interface EvidenceAvailability {
  total: number
  structuredEvidenceCount: number
  supportingEventsCount: number
  mitreMappingCount: number
}

/** Step 12N: DERIVED ANALYST VIEW -- deterministic presence checks over
 * the real, bounded GET /alerts response this page already fetched.
 * Measures ONLY whether a field is non-empty for each alert; never
 * whether the alert is confirmed, correctly detected, or malicious.
 * Deliberately framed as "Evidence Availability" -- presence of
 * structured evidence, supporting events, or a MITRE mapping says
 * nothing about detection correctness or threat confidence, and this
 * function must never be relabeled to imply otherwise.
 */
export function deriveEvidenceAvailability(alerts: AlertRead[]): EvidenceAvailability {
  let structuredEvidenceCount = 0
  let supportingEventsCount = 0
  let mitreMappingCount = 0
  for (const alert of alerts) {
    if (Object.keys(alert.evidence).length > 0) structuredEvidenceCount += 1
    if (alert.source_event_ids.length > 0) supportingEventsCount += 1
    if (getMitreTechniquesForRule(alert.rule_id).length > 0) mitreMappingCount += 1
  }
  return { total: alerts.length, structuredEvidenceCount, supportingEventsCount, mitreMappingCount }
}

/** The latest event_timestamp among the real, bounded GET /events page
 * already fetched -- null when no events were returned. Describes only
 * this bounded result set, never "the latest event system-wide."
 */
export function latestEventTimestamp(events: SecurityEventRead[]): string | null {
  if (events.length === 0) return null
  return events.reduce((latest, e) => (e.event_timestamp > latest ? e.event_timestamp : latest), events[0].event_timestamp)
}
