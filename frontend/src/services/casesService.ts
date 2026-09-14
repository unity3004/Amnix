import { apiRequest } from './httpClient'
import type {
  AlertListResponse,
  AlertRead,
  CaseAuditListResponse,
  CaseCreate,
  CaseListResponse,
  CaseNoteListResponse,
  CaseNoteResponse,
  CaseOwnerUpdate,
  CaseRead,
  CaseStatusUpdate,
  CaseUpdate,
  ListCasesParams,
} from '@/types/api'

/** GET /cases (Step 12R). Bounded, newest-first -- same shape as
 * listAlerts/listEvents.
 */
export function listCases(params: ListCasesParams = {}): Promise<CaseListResponse> {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) query.set(key, String(value))
  }
  const suffix = query.toString() ? `?${query.toString()}` : ''
  return apiRequest<CaseListResponse>(`/cases${suffix}`, { auth: true })
}

export function getCase(caseId: string): Promise<CaseRead> {
  return apiRequest<CaseRead>(`/cases/${caseId}`, { auth: true })
}

export function createCase(payload: CaseCreate): Promise<CaseRead> {
  return apiRequest<CaseRead>('/cases', { method: 'POST', body: payload, auth: true })
}

export function updateCase(caseId: string, payload: CaseUpdate): Promise<CaseRead> {
  return apiRequest<CaseRead>(`/cases/${caseId}`, { method: 'PATCH', body: payload, auth: true })
}

export function updateCaseStatus(caseId: string, payload: CaseStatusUpdate): Promise<CaseRead> {
  return apiRequest<CaseRead>(`/cases/${caseId}/status`, { method: 'PATCH', body: payload, auth: true })
}

export function updateCaseOwner(caseId: string, payload: CaseOwnerUpdate): Promise<CaseRead> {
  return apiRequest<CaseRead>(`/cases/${caseId}/owner`, { method: 'PATCH', body: payload, auth: true })
}

/** Real, linked Alert rows for one case -- reuses AlertListResponse/
 * AlertRead unmodified, exactly like the backend's own GET
 * /cases/{id}/alerts route.
 */
export function listCaseAlerts(caseId: string): Promise<AlertListResponse> {
  return apiRequest<AlertListResponse>(`/cases/${caseId}/alerts`, { auth: true })
}

export function linkCaseAlert(caseId: string, alertId: string): Promise<AlertRead> {
  return apiRequest<AlertRead>(`/cases/${caseId}/alerts`, {
    method: 'POST',
    body: { alert_id: alertId },
    auth: true,
  })
}

/** DELETE /cases/{id}/alerts/{alertId} -- unlinks the join row only,
 * never deletes the Alert itself. Returns 204 No Content.
 */
export function unlinkCaseAlert(caseId: string, alertId: string): Promise<void> {
  return apiRequest<void>(`/cases/${caseId}/alerts/${alertId}`, { method: 'DELETE', auth: true })
}

export function listCaseAudit(
  caseId: string,
  params: { limit?: number; offset?: number } = {},
): Promise<CaseAuditListResponse> {
  const query = new URLSearchParams()
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  if (params.offset !== undefined) query.set('offset', String(params.offset))
  const suffix = query.toString() ? `?${query.toString()}` : ''
  return apiRequest<CaseAuditListResponse>(`/cases/${caseId}/audit${suffix}`, { auth: true })
}

export function listCaseNotes(
  caseId: string,
  params: { limit?: number; offset?: number } = {},
): Promise<CaseNoteListResponse> {
  const query = new URLSearchParams()
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  if (params.offset !== undefined) query.set('offset', String(params.offset))
  const suffix = query.toString() ? `?${query.toString()}` : ''
  return apiRequest<CaseNoteListResponse>(`/cases/${caseId}/notes${suffix}`, { auth: true })
}

export function createCaseNote(caseId: string, body: string): Promise<CaseNoteResponse> {
  return apiRequest<CaseNoteResponse>(`/cases/${caseId}/notes`, { method: 'POST', body: { body }, auth: true })
}
