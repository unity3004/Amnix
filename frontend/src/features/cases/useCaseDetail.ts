import { useQuery } from '@tanstack/react-query'
import { getCase } from '@/services/casesService'

export function useCaseDetail(caseId: string | undefined) {
  return useQuery({
    queryKey: ['case-detail', caseId],
    queryFn: () => getCase(caseId as string),
    enabled: Boolean(caseId),
  })
}
