import type { CasePriority, CaseStatus } from '@/types/api'

/** Exactly the filter set GET /cases actually supports (Step 12R). */
export interface CasesFilters {
  status?: CaseStatus
  priority?: CasePriority
  owner_id?: string
}

export const CASE_STATUS_VALUES: CaseStatus[] = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED']
export const CASE_PRIORITY_VALUES: CasePriority[] = ['critical', 'high', 'medium', 'low']
