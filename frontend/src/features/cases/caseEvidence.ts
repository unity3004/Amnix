/**
 * Step 13A: pure, side-effect-free derivations over a Case's ALREADY-
 * fetched linked Alerts/Notes -- the same "no fetch, no invented field"
 * discipline as features/console/logic.ts (deriveDetectionSnapshot/
 * deriveInvestigationProgress are this file's direct precedent; this
 * file exists because CaseDetailPage itself has no equivalent, and the
 * Console's own versions are scoped to a "focused alert" investigation
 * fetch CaseDetailPage deliberately does not make -- see
 * deriveClosureReadiness's own docstring for why its checklist differs).
 *
 * Every count here is a real aggregate over `AlertRead[]`/`CaseNoteResponse[]`
 * already sitting in the query cache -- never a new request, never a
 * server-side total, never a percentage.
 */

import { getMitreTechniquesForRule } from '@/features/dashboard/mitreRegistry'
import type { AlertRead, CaseNoteResponse, CaseRead } from '@/types/api'

// ---------------------------------------------------------------------------
// Case Evidence Summary (§10) -- honest counts only, never "Total"/
// "Complete"/"Confirmed" Evidence, never a percentage.
// ---------------------------------------------------------------------------

export interface CaseEvidenceSummary {
  linkedAlerts: number
  alertsWithStructuredEvidence: number
  alertsWithSupportingEvents: number
  /** Distinct SecurityEvent ids reachable by unioning every linked
   * alert's own `source_event_ids` -- not a second fetch, not a new
   * relationship: the exact same ids AlertDetailPage's own "Supporting
   * Events" list already links to, just counted once each here.
   */
  securityEventsReachable: number
}

export function deriveCaseEvidenceSummary(alerts: AlertRead[]): CaseEvidenceSummary {
  return {
    linkedAlerts: alerts.length,
    alertsWithStructuredEvidence: alerts.filter((a) => Object.keys(a.evidence).length > 0).length,
    alertsWithSupportingEvents: alerts.filter((a) => a.source_event_ids.length > 0).length,
    securityEventsReachable: new Set(alerts.flatMap((a) => a.source_event_ids)).size,
  }
}

// ---------------------------------------------------------------------------
// Closure readiness checklist (§14) -- deterministic booleans only.
// NEVER a numeric score/percentage/confidence -- "Complete" means the
// documented-context checklist item is true, NOT that the incident is
// benign, malicious, or resolved. Completing every item does not close
// the case on its own; PATCH /cases/{id}/status remains the one real
// closing action (see CaseStatusPanel), and the backend's own
// closure_reason-required rule is never bypassed or duplicated here --
// this panel only reflects state the backend already enforces.
// ---------------------------------------------------------------------------

export interface ClosureReadinessItem {
  key: string
  label: string
  complete: boolean
}

/** Deliberately narrower than the Incident Console's own
 * deriveInvestigationProgress() (features/console/logic.ts): that
 * checklist's "Timeline available"/"Copilot consulted" items depend on
 * a focused-alert investigation/Copilot fetch the Console explicitly
 * supports (one analyst-selected alert at a time). CaseDetailPage has
 * no such focused-alert mechanism and must not add one just to populate
 * a checklist item -- so "MITRE mapped" (derivable from already-loaded
 * alerts alone, zero additional requests, and the same real rule
 * registry §12 asks to reuse) stands in for a literal "has investigation
 * available" item, which would otherwise be trivially true for any
 * linked alert and add no honest signal.
 */
export function deriveClosureReadiness(input: {
  caseItem: CaseRead
  alerts: AlertRead[]
  notes: CaseNoteResponse[]
}): ClosureReadinessItem[] {
  const items: ClosureReadinessItem[] = [
    { key: 'alert-linked', label: 'Has at least one linked alert', complete: input.alerts.length > 0 },
    {
      key: 'evidence-bearing-alert',
      label: 'Has an evidence-bearing alert',
      complete: input.alerts.some((a) => Object.keys(a.evidence).length > 0 || a.source_event_ids.length > 0),
    },
    {
      key: 'mitre-mapped',
      label: 'Has a MITRE-mapped alert',
      complete: input.alerts.some((a) => getMitreTechniquesForRule(a.rule_id).length > 0),
    },
    { key: 'notes-recorded', label: 'Has analyst notes', complete: input.notes.length > 0 },
  ]
  if (input.caseItem.status === 'CLOSED') {
    items.push({
      key: 'closure-reason-present',
      label: 'Closure reason present',
      complete: Boolean(input.caseItem.closure_reason && input.caseItem.closure_reason.trim().length > 0),
    })
  }
  return items
}
