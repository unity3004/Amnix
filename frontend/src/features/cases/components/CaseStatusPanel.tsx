import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { ApiError } from '@/services/httpClient'
import { updateCaseStatus } from '@/services/casesService'
import { describeCaseStatusAction, getAvailableCaseStatusActions } from '../caseLifecycle'
import type { CaseRead, CaseStatus } from '@/types/api'

const STATUS_TONE: Record<CaseStatus, 'accent' | 'neutral' | 'success' | 'warning'> = {
  OPEN: 'accent',
  INVESTIGATING: 'warning',
  RESOLVED: 'success',
  CLOSED: 'neutral',
}

/** The case's real lifecycle-changing action (PATCH /cases/{id}/status).
 * The buttons shown are exactly the backend's real next-transitions for
 * the case's CURRENT status (see caseLifecycle.ts) -- but the backend's
 * own 409/422 remains the authority, not this list: a rejected
 * transition re-syncs from the server rather than trusting local state.
 * Closing a case requires a non-blank closure_reason (backend-enforced);
 * this panel collects it inline before submitting that one transition.
 */
export function CaseStatusPanel({ caseItem }: { caseItem: CaseRead }) {
  const queryClient = useQueryClient()
  const [message, setMessage] = useState<{ tone: 'success' | 'error'; text: string } | null>(null)
  const [pendingStatus, setPendingStatus] = useState<CaseStatus | null>(null)
  const [showClosureForm, setShowClosureForm] = useState(false)
  const [closureReason, setClosureReason] = useState('')

  const mutation = useMutation({
    mutationFn: (input: { status: CaseStatus; closureReason?: string }) =>
      updateCaseStatus(caseItem.id, { status: input.status, closure_reason: input.closureReason ?? null }),
    onMutate: (input) => {
      setPendingStatus(input.status)
      setMessage(null)
    },
    onSuccess: (updated) => {
      queryClient.setQueryData(['case-detail', caseItem.id], updated)
      queryClient.invalidateQueries({ queryKey: ['cases-list'] })
      queryClient.invalidateQueries({ queryKey: ['case-audit', caseItem.id] })
      setMessage({ tone: 'success', text: 'Case status updated.' })
      setShowClosureForm(false)
      setClosureReason('')
    },
    onError: (error) => {
      // Re-sync from the server on ANY failure (no optimistic-locking
      // version field exists on Case -- see this module's own docstring
      // -- so a stale local read is only ever caught by re-validating
      // against the live state the backend just reported).
      queryClient.invalidateQueries({ queryKey: ['case-detail', caseItem.id] })
      // 409 is the exact "another actor already moved this case" race
      // the docstring above designs around -- its backend message (e.g.
      // "Cannot transition case status from 'X' to 'Y'") is the one
      // piece of information that actually explains what just happened,
      // so it -- like the closure-reason 422 -- is shown verbatim rather
      // than collapsed into the generic fallback.
      const text =
        error instanceof ApiError && (error.status === 409 || error.status === 422)
          ? error.message
          : 'Case status could not be updated.'
      setMessage({ tone: 'error', text })
    },
    onSettled: () => {
      setPendingStatus(null)
    },
  })

  const availableActions = getAvailableCaseStatusActions(caseItem.status)

  function handleAction(next: CaseStatus) {
    if (next === 'CLOSED') {
      setShowClosureForm(true)
      return
    }
    mutation.mutate({ status: next })
  }

  return (
    <>
      <CardHeader title="Case Status" subtitle="Update the case lifecycle as the investigation progresses." />

      <div className="px-5">
        <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Current Status</p>
        <div className="mt-1.5">
          <Badge tone={STATUS_TONE[caseItem.status]} dot>
            {caseItem.status}
          </Badge>
        </div>
        {caseItem.status === 'CLOSED' && caseItem.closure_reason && (
          <p className="mt-1.5 text-xs text-fg-subtle">Closure reason: {caseItem.closure_reason}</p>
        )}
      </div>

      <div className="mt-4 px-5 pb-5">
        <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Available Actions</p>
        {availableActions.length === 0 ? (
          <p className="mt-1.5 text-xs text-fg-subtle">No further status changes are available.</p>
        ) : (
          <div className="mt-2 flex flex-col gap-2">
            {availableActions.map((next) => {
              const copy = describeCaseStatusAction(caseItem.status, next)
              return (
                <div key={next} className="flex flex-wrap items-center gap-2">
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    disabled={mutation.isPending}
                    onClick={() => handleAction(next)}
                  >
                    {mutation.isPending && pendingStatus === next ? 'Updating…' : copy.label}
                  </Button>
                  <span className="text-xs text-fg-subtle">{copy.description}</span>
                </div>
              )
            })}
          </div>
        )}

        {showClosureForm && (
          <div className="mt-3 flex flex-col gap-2 rounded-md border border-border-faint bg-bg-inset p-3">
            <label htmlFor="case-closure-reason" className="text-[11px] uppercase tracking-wide text-fg-subtle">
              Closure Reason (required)
            </label>
            <textarea
              id="case-closure-reason"
              rows={2}
              className="w-full rounded-md border border-border bg-surface px-3 py-2 text-sm text-fg placeholder:text-fg-subtle focus:border-accent/50 focus:outline-none"
              value={closureReason}
              onChange={(e) => setClosureReason(e.target.value)}
            />
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="primary"
                size="sm"
                disabled={mutation.isPending || !closureReason.trim()}
                onClick={() => mutation.mutate({ status: 'CLOSED', closureReason: closureReason.trim() })}
              >
                {mutation.isPending ? 'Closing…' : 'Confirm Close'}
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => {
                  setShowClosureForm(false)
                  setClosureReason('')
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        )}

        <div aria-live="polite" className="mt-2 min-h-[1rem] text-xs">
          {mutation.isPending && <span className="text-fg-subtle">Updating case status…</span>}
          {!mutation.isPending && message && (
            <span className={message.tone === 'success' ? 'text-success' : 'text-danger'}>{message.text}</span>
          )}
        </div>
      </div>
    </>
  )
}
