/**
 * Step 13C: pure, deterministic derivations for the Case Summary &
 * Incident Narrative -- same discipline as caseEvidence.ts (Step 13A)
 * and features/console/logic.ts (Step 12W): every function here takes
 * REAL, already-loaded data (AlertRead[], CaseNoteResponse[], CaseRead)
 * and returns a derived view -- never a fetch, never an invented field,
 * never a score/probability/verdict. This is application-generated
 * orientation text, not an AI-generated conclusion -- see
 * CaseSummaryPanel's own provenance note, which states this explicitly
 * to the analyst.
 *
 * Detection-rule grouping (DetectionRulesPanel) and MITRE-tactic
 * grouping (MitreCoveragePanel) are deliberately NOT reimplemented here
 * -- CaseSummaryPanel reuses those two existing, self-contained Step
 * 12W components verbatim (fed by deriveParticipatingRules/
 * groupMitreByTactic from console/logic.ts), per this step's own
 * explicit "prefer one reusable implementation" instruction.
 */

import { getRuleDefinition } from '@/features/rules/ruleRegistry'
import type { AlertRead, CaseNoteResponse, CaseRead } from '@/types/api'

export interface TemporalSummary {
  /** Earliest linked alert's first_seen, or null with zero alerts. */
  earliest: string | null
  /** Latest linked alert's last_seen, or null with zero alerts. */
  latest: string | null
}

/** Step 13C §10: "Observed telemetry range", deliberately built from
 * Alert.first_seen/last_seen (already loaded, zero additional request)
 * rather than exact per-SecurityEvent timestamps -- Alert.first_seen/
 * last_seen already represent "when the underlying behavior was first/
 * most-recently observed" (see app/models/alert.py's own docstring), so
 * this is a genuine, real telemetry-adjacent range, just a case-wide
 * approximation rather than per-event precision. Fetching every linked
 * alert's own Investigation to get exact per-event timestamps would be
 * the N+1 pattern this codebase has repeatedly ruled out (see Step 13B's
 * own architectural note) -- the Case Timeline's focused-alert view
 * remains the place to see a specific alert's real, per-event timeline.
 * Never MTTD/MTTR/"attack duration" -- no causal claim is made.
 */
export function deriveTemporalSummary(alerts: AlertRead[]): TemporalSummary {
  if (alerts.length === 0) return { earliest: null, latest: null }
  let earliest = alerts[0].first_seen
  let latest = alerts[0].last_seen
  for (const alert of alerts) {
    if (new Date(alert.first_seen).getTime() < new Date(earliest).getTime()) earliest = alert.first_seen
    if (new Date(alert.last_seen).getTime() > new Date(latest).getTime()) latest = alert.last_seen
  }
  return { earliest, latest }
}

/** Step 13C §5: a short, deterministic narrative -- Detection / Telemetry
 * / Investigation / Analyst Documentation / Current State, each one
 * plain sentence built only from real counts over already-loaded
 * AlertRead[]/CaseNoteResponse[]/CaseRead. Never claims causality
 * ("the attacker..."), never a verdict -- only what the linked alerts,
 * their own recorded evidence/event references, and the case's own real
 * fields actually establish.
 */
export function deriveIncidentNarrative(input: { caseItem: CaseRead; alerts: AlertRead[]; notes: CaseNoteResponse[] }): string[] {
  const { caseItem, alerts, notes } = input
  const lines: string[] = []

  if (alerts.length === 0) {
    lines.push('No alerts are currently linked to this case.')
  } else {
    const ruleNames = Array.from(new Set(alerts.map((a) => a.rule_id))).map((ruleId) => getRuleDefinition(ruleId)?.name ?? ruleId)
    const preview = ruleNames.slice(0, 3).join(', ')
    lines.push(
      `This case contains ${alerts.length} linked alert${alerts.length === 1 ? '' : 's'}, including ${preview}${
        ruleNames.length > 3 ? ', and other rules' : ''
      }.`,
    )

    const eventCount = new Set(alerts.flatMap((a) => a.source_event_ids)).size
    lines.push(
      eventCount > 0
        ? `The linked alerts reference ${eventCount} distinct security event${eventCount === 1 ? '' : 's'}.`
        : 'The linked alerts do not currently reference any supporting security events.',
    )

    const evidenceBearing = alerts.filter((a) => a.source_event_ids.length > 0 || Object.keys(a.evidence).length > 0).length
    lines.push(
      evidenceBearing > 0
        ? `${evidenceBearing} of ${alerts.length} linked alert${alerts.length === 1 ? '' : 's'} ${
            evidenceBearing === 1 ? 'has' : 'have'
          } supporting telemetry or structured evidence available for investigation.`
        : 'None of the linked alerts currently have supporting telemetry or structured evidence recorded.',
    )
  }

  lines.push(
    notes.length > 0
      ? `${notes.length} analyst note${notes.length === 1 ? ' has' : 's have'} been recorded.`
      : 'No analyst notes have been recorded yet.',
  )

  lines.push(
    `The case is currently ${caseItem.status} with ${caseItem.priority} priority and ${
      caseItem.owner_id ? 'an assigned owner' : 'no assigned owner'
    }.`,
  )

  return lines
}

/** Step 13C §13: deterministic workflow-state guidance only -- never a
 * claim that an attack was confirmed, a threat contained, or a system
 * safe. Each message traces directly to a real, already-loaded count or
 * the case's own real `status` field.
 */
export function deriveOpenItems(input: { caseItem: CaseRead; alerts: AlertRead[]; notes: CaseNoteResponse[] }): string[] {
  const { caseItem, alerts, notes } = input
  const items: string[] = []

  if (alerts.length === 0) items.push('No alerts are linked to this case.')
  if (alerts.length > 0 && notes.length === 0) items.push('No analyst notes have been recorded.')

  switch (caseItem.status) {
    case 'OPEN':
      items.push('Case investigation is still open.')
      break
    case 'INVESTIGATING':
      items.push('Continue reviewing linked evidence and documenting findings.')
      break
    case 'RESOLVED':
      items.push('Case is resolved but not yet closed.')
      break
    case 'CLOSED':
      items.push('Case is closed.')
      break
  }

  return items
}
