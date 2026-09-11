import { apiRequest } from './httpClient'
import type { ListEventsParams, SecurityEventCreate, SecurityEventListResponse, SecurityEventRead } from '@/types/api'

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
