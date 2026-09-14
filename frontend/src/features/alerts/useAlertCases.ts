import { useQuery } from '@tanstack/react-query'
import { getAlertCases } from '@/services/alertsService'

/** GET /alerts/{id}/cases (Step 12V) -- fetched once when Alert Detail
 * opens, never per-row on any alert list. Query key includes the alert
 * ID so CaseAlertsPanel/LinkAlertToCasePanel's own link/unlink mutations
 * can invalidate exactly this alert's entry (see those components' own
 * onSuccess handlers) without a global cache flush.
 */
export function useAlertCases(alertId: string | undefined) {
  return useQuery({
    queryKey: ['alert-cases', alertId],
    queryFn: () => getAlertCases(alertId as string),
    enabled: Boolean(alertId),
  })
}
