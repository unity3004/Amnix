import { apiRequest } from './httpClient'
import type { AdminAuditAction, AdminAuditListResponse, UserRead } from '@/types/api'

export function getAdminAudits(
  params: { limit?: number; offset?: number; actor_user_id?: string; target_user_id?: string; action?: AdminAuditAction } = {},
): Promise<AdminAuditListResponse> {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) query.set(key, String(value))
  }
  const suffix = query.toString() ? `?${query.toString()}` : ''
  return apiRequest<AdminAuditListResponse>(`/admin/audits${suffix}`, { auth: true })
}

export function updateUserStatus(userId: string, isActive: boolean): Promise<UserRead> {
  return apiRequest<UserRead>(`/admin/users/${userId}/status`, {
    method: 'PATCH',
    body: { is_active: isActive },
    auth: true,
  })
}
