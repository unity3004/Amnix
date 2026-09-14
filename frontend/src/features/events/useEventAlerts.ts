import { useQuery } from '@tanstack/react-query'
import { getEventAlerts } from '@/services/eventsService'

/** GET /events/{id}/alerts (Step 12Y) -- fetched once per event the
 * analyst actually inspects (Event Detail page mount, or explicit Threat
 * Hunting inspector selection), never per-row on any event list. Query
 * key includes the event ID so a different selection never reuses a
 * stale cache entry.
 */
export function useEventAlerts(eventId: string | undefined) {
  return useQuery({
    queryKey: ['event-alerts', eventId],
    queryFn: () => getEventAlerts(eventId as string),
    enabled: Boolean(eventId),
  })
}
