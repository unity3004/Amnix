import { useQuery } from '@tanstack/react-query'
import { listCaseNotes } from '@/services/casesService'

export function useCaseNotes(caseId: string | undefined) {
  return useQuery({
    queryKey: ['case-notes', caseId],
    queryFn: () => listCaseNotes(caseId as string, { limit: 200 }),
    enabled: Boolean(caseId),
  })
}
