import type { SecurityEventRead } from '@/types/api'
import type { LiveEventSummary } from '../types'

/** Maps real SecurityEventRead rows (already newest-first -- see
 * SecurityEventRepository.list_recent()) into the Live Event Stream
 * panel's display shape. Every field here exists on SecurityEventRead
 * itself -- nothing is invented or backfilled.
 */
export function deriveEventStream(events: SecurityEventRead[]): LiveEventSummary[] {
  return events.map((event) => ({
    id: event.id,
    eventType: event.event_type,
    source: event.source,
    hostname: event.hostname ?? null,
    username: event.username ?? null,
    sourceIp: event.source_ip ?? null,
    timestamp: event.event_timestamp,
  }))
}
