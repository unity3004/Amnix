import { useQuery } from '@tanstack/react-query'
import { getEvent } from '@/services/eventsService'

export function useEventDetail(eventId: string | undefined) {
  return useQuery({
    queryKey: ['event-detail', eventId],
    queryFn: () => getEvent(eventId as string),
    enabled: Boolean(eventId),
  })
}
