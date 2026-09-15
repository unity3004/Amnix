import type { AlertRead } from '@/types/api'

/** Case-scoped counterpart to features/investigation/eventRefMap.ts's
 * `buildEventRefMap` -- `alert_ref` labels ("alert-1", "alert-2", ...)
 * are synthetic, request-scoped positions AICaseContextBuilder assigns
 * from the SAME ordered list GET /cases/{id}/alerts already returns (see
 * backend/app/services/case_copilot_service.py::ask_about_case, which
 * builds context from `case_service.list_alerts(case_id)` -- the exact
 * call this page's own alertsData already made). Fully computable
 * client-side from data already in memory; no additional request, and
 * never a real database id sent to or trusted from the AI layer.
 */
export function buildAlertRefMap(alerts: AlertRead[]): Map<string, string> {
  const map = new Map<string, string>()
  alerts.forEach((alert, index) => map.set(`alert-${index + 1}`, alert.id))
  return map
}
