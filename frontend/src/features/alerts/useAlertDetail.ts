import { useQuery } from '@tanstack/react-query'
import { getAlert } from '@/services/alertsService'

export function useAlertDetail(alertId: string | undefined) {
  return useQuery({
    queryKey: ['alert-detail', alertId],
    queryFn: () => getAlert(alertId as string),
    enabled: Boolean(alertId),
  })
}
