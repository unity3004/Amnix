import type { AlertRead, AlertStatus } from '@/types/api'
import type { InvestigationStage, InvestigationStageGroup } from '../types'
import { deriveActiveThreats } from './deriveActiveThreats'

/** Maps AMNIX's real 5-value AlertStatus lifecycle (new / acknowledged
 * / investigating / resolved / escalated -- see
 * backend/app/models/alert.py's CHECK constraint) onto the 3-stage
 * workflow view the brief asks for. `escalated` is grouped under
 * "investigating", not "resolved" -- an escalated alert has MORE
 * analyst attention on it, not less; it is still actively being
 * worked, just with heightened priority.
 */
const STAGE_BY_STATUS: Record<AlertStatus, InvestigationStage> = {
  new: 'new',
  acknowledged: 'investigating',
  investigating: 'investigating',
  escalated: 'investigating',
  resolved: 'resolved',
}

const STAGE_LABELS: Record<InvestigationStage, string> = {
  new: 'New',
  investigating: 'Investigating',
  resolved: 'Resolved',
}

const STAGE_ORDER: InvestigationStage[] = ['new', 'investigating', 'resolved']

/** Groups the CURRENTLY RETRIEVED bounded GET /alerts page by lifecycle
 * stage -- derived purely from Alert.status, never from a per-alert
 * GET /alerts/{id}/investigation request (the brief explicitly
 * prohibits an N+1 investigation fetch here; the full investigation
 * timeline remains the dedicated investigation page's job).
 */
export function deriveInvestigationActivity(alerts: AlertRead[]): InvestigationStageGroup[] {
  return STAGE_ORDER.map((stage) => ({
    stage,
    label: STAGE_LABELS[stage],
    alerts: deriveActiveThreats(alerts.filter((alert) => STAGE_BY_STATUS[alert.status] === stage)),
  }))
}
