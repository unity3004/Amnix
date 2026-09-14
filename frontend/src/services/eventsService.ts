import { apiRequest } from './httpClient'
import type {
  AlertListResponse,
  ListEventsParams,
  SecurityEventCreate,
  SecurityEventListResponse,
  SecurityEventRead,
} from '@/types/api'

export function getEvent(eventId: string): Promise<SecurityEventRead> {
  return apiRequest<SecurityEventRead>(`/events/${eventId}`, { auth: true })
}

export function createEvent(payload: SecurityEventCreate): Promise<SecurityEventRead> {
  return apiRequest<SecurityEventRead>('/events', { method: 'POST', body: payload, auth: true })
}

/** GET /events (Step 12B). Bounded, newest-first. See ListEventsParams
 * for the exact filter set the backend actually supports -- nothing
 * here is invented beyond that contract.
 */
export function listEvents(params: ListEventsParams = {}): Promise<SecurityEventListResponse> {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) query.set(key, String(value))
  }
  const suffix = query.toString() ? `?${query.toString()}` : ''
  return apiRequest<SecurityEventListResponse>(`/events${suffix}`, { auth: true })
}

/** GET /events/{id}/alerts (Step 12Y) -- the authoritative reverse
 * relationship: real, persisted Alerts that genuinely cite this
 * SecurityEvent as evidence, via the backend's own alert_security_events
 * join. Never derived client-side from rule_id/timestamp/field matching.
 */
export function getEventAlerts(
  eventId: string,
  params: { limit?: number; offset?: number } = {},
): Promise<AlertListResponse> {
  const query = new URLSearchParams()
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  if (params.offset !== undefined) query.set('offset', String(params.offset))
  const suffix = query.toString() ? `?${query.toString()}` : ''
  return apiRequest<AlertListResponse>(`/events/${eventId}/alerts${suffix}`, { auth: true })
}
