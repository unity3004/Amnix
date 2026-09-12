import type { AlertStatus } from '@/types/api'

/**
 * Static, hand-verified mirror of the real backend alert lifecycle state
 * machine (backend/app/services/alert_lifecycle.py::ALERT_STATUS_TRANSITIONS).
 * The backend's assert_valid_transition() remains the one source of
 * truth for which transitions are actually allowed -- this mirror exists
 * only so the "Available Analyst Actions" UI doesn't offer a button the
 * backend would reject. If this mirror ever drifts from the real
 * backend graph, an attempted transition still comes back as a safe 409
 * (see AnalystDecisionPanel's error handling), never as a silently
 * accepted illegal status change -- the backend is authoritative, this
 * is presentation only.
 */
export const ALERT_STATUS_TRANSITIONS: Record<AlertStatus, AlertStatus[]> = {
  new: ['acknowledged', 'investigating', 'escalated'],
  acknowledged: ['investigating', 'escalated'],
  investigating: ['resolved', 'escalated'],
  escalated: ['resolved'],
  resolved: [],
}

export const ALERT_STATUS_ACTION_LABEL: Record<AlertStatus, string> = {
  new: 'Mark New',
  acknowledged: 'Acknowledge',
  investigating: 'Start Investigating',
  resolved: 'Resolve',
  escalated: 'Escalate',
}

export function getAvailableAlertStatusActions(current: AlertStatus): AlertStatus[] {
  return ALERT_STATUS_TRANSITIONS[current] ?? []
}
