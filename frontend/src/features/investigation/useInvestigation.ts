import { useQuery } from '@tanstack/react-query'
import { getAlertInvestigation } from '@/services/alertsService'

/** GET /alerts/{id}/investigation -- fetched once when the analyst opens
 * the workspace for this alert, never polled and never fetched per-row
 * (see InvestigationWorkspacePage, the only caller). Reuses the exact
 * same service function InvestigationsPage already used.
 */
export function useInvestigation(alertId: string | undefined) {
  return useQuery({
    queryKey: ['investigation', alertId],
    queryFn: () => getAlertInvestigation(alertId as string),
    enabled: Boolean(alertId),
  })
}
