import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { useAuth } from '@/features/auth/useAuth'
import { ApiError } from '@/services/httpClient'
import { updateCaseOwner } from '@/services/casesService'
import type { CaseRead } from '@/types/api'

/** PATCH /cases/{id}/owner (Step 12R/12S). Object-level authorization is
 * entirely server-enforced by CaseService.change_owner -- this panel
 * only decides which controls to SHOW (an analyst is only ever offered
 * self-assign/release, matching the two actions the backend actually
 * permits them); the backend's own 403 remains authoritative regardless
 * of what this panel renders.
 *
 * There is no GET /admin/users list endpoint anywhere in AMNIX (verified
 * by source inspection) -- rather than fabricate a user picker, an admin
 * reassigning to someone other than themselves types the target user's
 * real ID directly; CaseService validates that ID exists and is active
 * before applying it.
 */
export function CaseOwnerPanel({ caseItem }: { caseItem: CaseRead }) {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [message, setMessage] = useState<{ tone: 'success' | 'error'; text: string } | null>(null)
  const [assignUserId, setAssignUserId] = useState('')

  const mutation = useMutation({
    mutationFn: (ownerId: string | null) => updateCaseOwner(caseItem.id, { owner_id: ownerId }),
    onSuccess: (updated) => {
      queryClient.setQueryData(['case-detail', caseItem.id], updated)
      queryClient.invalidateQueries({ queryKey: ['cases-list'] })
      queryClient.invalidateQueries({ queryKey: ['case-audit', caseItem.id] })
      setMessage({ tone: 'success', text: 'Case ownership updated.' })
      setAssignUserId('')
    },
    onError: (error) => {
      queryClient.invalidateQueries({ queryKey: ['case-detail', caseItem.id] })
      const text =
        error instanceof ApiError && (error.status === 403 || error.status === 404 || error.status === 422)
          ? error.message
          : 'Case ownership could not be updated.'
      setMessage({ tone: 'error', text })
    },
  })

  if (!user) return null

  const isAdmin = user.role === 'admin'
  const isUnowned = caseItem.owner_id === null
  const isOwnedBySelf = caseItem.owner_id === user.id

  return (
    <>
      <CardHeader title="Case Owner" subtitle="Who is currently responsible for this case." />

      <div className="px-5">
        <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Current Owner</p>
        <p className="mt-1.5 font-mono text-xs text-fg-muted" title={caseItem.owner_id ?? undefined}>
          {isUnowned ? 'Unassigned' : isOwnedBySelf ? 'You' : caseItem.owner_id}
        </p>
      </div>

      <div className="mt-4 flex flex-col gap-3 px-5 pb-5">
        <div className="flex flex-wrap gap-2">
          {isUnowned && (
            <Button
              type="button"
              variant="secondary"
              size="sm"
              disabled={mutation.isPending}
              onClick={() => mutation.mutate(user.id)}
            >
              Assign to Me
            </Button>
          )}
          {(isOwnedBySelf || (isAdmin && !isUnowned)) && (
            <Button
              type="button"
              variant="secondary"
              size="sm"
              disabled={mutation.isPending}
              onClick={() => mutation.mutate(null)}
            >
              Release Ownership
            </Button>
          )}
        </div>

        {isAdmin && (
          <div className="flex items-end gap-2">
            <div className="flex-1">
              <label htmlFor="case-assign-user-id" className="text-[11px] uppercase tracking-wide text-fg-subtle">
                Assign to User ID (admin)
              </label>
              <input
                id="case-assign-user-id"
                type="text"
                placeholder="User UUID"
                value={assignUserId}
                onChange={(e) => setAssignUserId(e.target.value)}
                className="mt-1 w-full rounded-md border border-border bg-surface px-3 py-1.5 font-mono text-xs text-fg placeholder:text-fg-subtle focus:border-accent/50 focus:outline-none"
              />
            </div>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              disabled={mutation.isPending || !assignUserId.trim()}
              onClick={() => mutation.mutate(assignUserId.trim())}
            >
              Assign
            </Button>
          </div>
        )}

        {!isAdmin && !isUnowned && !isOwnedBySelf && (
          <p className="text-xs text-fg-subtle">This case is owned by another analyst.</p>
        )}

        <div aria-live="polite" className="min-h-[1rem] text-xs">
          {mutation.isPending && <span className="text-fg-subtle">Updating case owner…</span>}
          {!mutation.isPending && message && (
            <span className={message.tone === 'success' ? 'text-success' : 'text-danger'}>{message.text}</span>
          )}
        </div>
      </div>
    </>
  )
}
