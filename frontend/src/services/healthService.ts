import { apiRequest } from './httpClient'

export interface HealthResponse {
  status: string
  service: string
}

/** GET /health is real, public, and unauthenticated (see
 * backend/app/api/health.py) — used as-is for the dashboard's "API"
 * status indicator. It does NOT report on Database/Redis/AI Provider
 * sub-dependencies (confirmed by reading the real handler: it returns a
 * static status/service pair only) — SystemStatusPanel labels those
 * three as "not monitored" rather than fabricating a healthy/unhealthy
 * signal the backend does not actually provide (brief §19).
 */
export function getHealth(): Promise<HealthResponse> {
  return apiRequest<HealthResponse>('/health')
}
