import { useQuery } from '@tanstack/react-query'
import { listCaseAudit } from '@/services/casesService'

export function useCaseAudit(caseId: string | undefined) {
  return useQuery({
    queryKey: ['case-audit', caseId],
    queryFn: () => listCaseAudit(caseId as string, { limit: 200 }),
    enabled: Boolean(caseId),
  })
}
