import { useQuery } from '@tanstack/react-query'
import { getCopilotAudits } from '@/services/alertsService'

/** GET /alerts/{id}/copilot/audits -- fetched only for the Incident
 * Console's currently-focused alert (see useIncidentConsole.ts), never
 * looped across every alert linked to a case. `enabled` is false while
 * no alert is focused, so this never fires on page load by itself.
 */
export function useAlertCopilotAudits(alertId: string | undefined) {
  return useQuery({
    queryKey: ['alert-copilot-audits', alertId],
    queryFn: () => getCopilotAudits(alertId as string, { limit: 50 }),
    enabled: Boolean(alertId),
  })
}
