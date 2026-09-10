import { apiRequest } from './httpClient'
import type {
  AlertRead,
  AlertStatus,
  CopilotAuditListResponse,
  CopilotFollowUpRequest,
  CopilotFollowUpResponse,
  CopilotResponse,
  InvestigationContext,
} from '@/types/api'

export function getAlert(alertId: string): Promise<AlertRead> {
  return apiRequest<AlertRead>(`/alerts/${alertId}`, { auth: true })
}

export function updateAlertStatus(alertId: string, status: AlertStatus): Promise<AlertRead> {
  return apiRequest<AlertRead>(`/alerts/${alertId}/status`, { method: 'PATCH', body: { status }, auth: true })
}

export function getAlertInvestigation(alertId: string): Promise<InvestigationContext> {
  return apiRequest<InvestigationContext>(`/alerts/${alertId}/investigation`, { auth: true })
}

export function askCopilot(alertId: string, question: string): Promise<CopilotResponse> {
  return apiRequest<CopilotResponse>(`/alerts/${alertId}/copilot`, {
    method: 'POST',
    body: { question },
    auth: true,
  })
}

export function askCopilotFollowUp(
  alertId: string,
  payload: CopilotFollowUpRequest,
): Promise<CopilotFollowUpResponse> {
  return apiRequest<CopilotFollowUpResponse>(`/alerts/${alertId}/copilot/follow-up`, {
    method: 'POST',
    body: payload,
    auth: true,
  })
}

export function getCopilotAudits(
  alertId: string,
  params: { limit?: number; offset?: number } = {},
): Promise<CopilotAuditListResponse> {
  const query = new URLSearchParams()
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  if (params.offset !== undefined) query.set('offset', String(params.offset))
  const suffix = query.toString() ? `?${query.toString()}` : ''
  return apiRequest<CopilotAuditListResponse>(`/alerts/${alertId}/copilot/audits${suffix}`, { auth: true })
}
