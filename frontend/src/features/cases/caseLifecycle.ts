import type { CaseStatus } from '@/types/api'

/**
 * Static, hand-verified mirror of the real backend case lifecycle state
 * machine (backend/app/services/case_lifecycle.py::CASE_STATUS_TRANSITIONS).
 * The backend's assert_valid_transition() remains the one source of
 * truth for which transitions are actually allowed -- this mirror exists
 * only so the status control never offers a button the backend would
 * reject. If this mirror ever drifts from the real backend graph, an
 * attempted transition still comes back as a safe 409, never a silently
 * accepted illegal status change -- the backend is authoritative, this
 * is presentation only. See features/alerts/alertStatusTransitions.ts
 * for the identical precedent this mirrors.
 */
export const CASE_STATUS_TRANSITIONS: Record<CaseStatus, CaseStatus[]> = {
  OPEN: ['INVESTIGATING'],
  INVESTIGATING: ['RESOLVED'],
  RESOLVED: ['INVESTIGATING', 'CLOSED'],
  CLOSED: ['INVESTIGATING'],
}

export function getAvailableCaseStatusActions(current: CaseStatus): CaseStatus[] {
  return CASE_STATUS_TRANSITIONS[current] ?? []
}

export interface CaseStatusActionCopy {
  label: string
  description: string
}

/**
 * Label/description keyed by the (current, next) PAIR, not just `next`
 * alone -- INVESTIGATING is the target of two operationally different
 * transitions (RESOLVED -> INVESTIGATING vs CLOSED -> INVESTIGATING),
 * and the backend itself already treats them as different real events:
 * CaseService.change_status records the former as a plain
 * CASE_STATUS_CHANGED audit row (case_lifecycle.py's own docstring:
 * "does NOT represent a reopen of a closed case") and the latter as a
 * distinct CASE_REOPENED row that also clears closed_at/closure_reason.
 * Collapsing both into one "Reopen" label would misrepresent what the
 * backend is actually about to do -- this mirrors that real distinction
 * rather than inventing a new one.
 */
const ACTION_COPY: Record<CaseStatus, Partial<Record<CaseStatus, CaseStatusActionCopy>>> = {
  OPEN: {
    INVESTIGATING: { label: 'Start Investigating', description: 'Begin active investigation of this case.' },
  },
  INVESTIGATING: {
    RESOLVED: { label: 'Resolve', description: 'Mark the investigation complete, pending formal closure.' },
  },
  RESOLVED: {
    INVESTIGATING: {
      label: 'Return to Investigating',
      description: 'More work is needed before this case can be closed.',
    },
    CLOSED: { label: 'Close Case', description: 'Formally close this case. Requires a closure reason.' },
  },
  CLOSED: {
    INVESTIGATING: { label: 'Reopen Case', description: 'New information has surfaced on this closed case.' },
  },
}

export function describeCaseStatusAction(current: CaseStatus, next: CaseStatus): CaseStatusActionCopy {
  return ACTION_COPY[current]?.[next] ?? { label: next, description: '' }
}
