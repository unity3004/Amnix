import { apiRequest } from './httpClient'
import type { SecurityEventCreate, SecurityEventRead } from '@/types/api'

export function getEvent(eventId: string): Promise<SecurityEventRead> {
  return apiRequest<SecurityEventRead>(`/events/${eventId}`, { auth: true })
}

export function createEvent(payload: SecurityEventCreate): Promise<SecurityEventRead> {
  return apiRequest<SecurityEventRead>('/events', { method: 'POST', body: payload, auth: true })
}
