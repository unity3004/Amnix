import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { listAlerts } from '@/services/alertsService'

const RULE_ALERTS_PAGE_SIZE = 10

/** Rule -> Alert relationship (Step 12H). Uses the existing, already
 *-supported GET /alerts?rule_id=... (Step 12B) -- no new backend
 * endpoint. Fetched only when the analyst opens a Rule Detail page,
 * never per rule-list-row (see RuleExplorerPage, which never calls
 * this). Bounded, newest-first, no total -- same "no COUNT(*)"
 * contract as AlertsPage's own list.
 */
export function useRuleAlerts(ruleId: string | undefined, page: number) {
  const offset = (page - 1) * RULE_ALERTS_PAGE_SIZE

  const query = useQuery({
    queryKey: ['rule-alerts', ruleId, page],
    queryFn: () => listAlerts({ rule_id: ruleId, limit: RULE_ALERTS_PAGE_SIZE, offset }),
    enabled: Boolean(ruleId),
    placeholderData: keepPreviousData,
  })

  return {
    alerts: query.data?.items ?? [],
    hasNextPage: (query.data?.items.length ?? 0) === RULE_ALERTS_PAGE_SIZE,
    isPending: query.isPending,
    isError: query.isError,
    refetch: query.refetch,
  }
}

export { RULE_ALERTS_PAGE_SIZE }
