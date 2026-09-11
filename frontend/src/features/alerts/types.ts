import type { AlertStatus, DetectionSeverity } from '@/types/api'

/** Exactly the filter set GET /alerts actually supports (Step 12B) --
 * nothing here may be added without a corresponding backend query
 * parameter.
 */
export interface AlertsFilters {
  status?: AlertStatus
  severity?: DetectionSeverity
  rule_id?: string
  since?: string
  until?: string
}

export const ALERT_STATUS_VALUES: AlertStatus[] = ['new', 'acknowledged', 'investigating', 'resolved', 'escalated']
export const ALERT_SEVERITY_VALUES: DetectionSeverity[] = ['critical', 'high', 'medium', 'low']
