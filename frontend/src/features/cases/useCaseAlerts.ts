import { useQuery } from '@tanstack/react-query'
import { listCaseAlerts } from '@/services/casesService'

export function useCaseAlerts(caseId: string | undefined) {
  return useQuery({
    queryKey: ['case-alerts', caseId],
    queryFn: () => listCaseAlerts(caseId as string),
    enabled: Boolean(caseId),
  })
}
