import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { updateAlertStatus } from '@/services/alertsService'
import { getAvailableAlertStatusActions, ALERT_STATUS_ACTION_LABEL } from '../alertStatusTransitions'
import type { AlertRead, AlertStatus } from '@/types/api'

const STATUS_TONE: Record<AlertStatus, 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

/** Step 12L: the analyst's actual decision point -- distinct from every
 * read-only section above it (rule, evidence, MITRE, investigation).
 * Uses only the existing PATCH /alerts/{id}/status endpoint; the buttons
 * shown are exactly the backend's real next-transitions for the alert's
 * CURRENT status (see alertStatusTransitions.ts), so this never offers
 * an action the backend would reject -- but the backend's own 409 is
 * still the authority, not this list (see onError below: a rejected
 * transition re-syncs from the server rather than trusting local state,
 * since there is no optimistic-locking/version field on Alert to detect
 * a stale read any other way -- see the Step 12L report's Concurrency
 * Findings for why that gap is documented, not invented around).
 */
export function AnalystDecisionPanel({ alert }: { alert: AlertRead }) {
  const queryClient = useQueryClient()
  const [message, setMessage] = useState<{ tone: 'success' | 'error'; text: string } | null>(null)
  const [pendingStatus, setPendingStatus] = useState<AlertStatus | null>(null)

  const mutation = useMutation({
    mutationFn: (nextStatus: AlertStatus) => updateAlertStatus(alert.id, nextStatus),
    onMutate: (nextStatus: AlertStatus) => {
      setPendingStatus(nextStatus)
      setMessage(null)
    },
    onSuccess: (updated) => {
      queryClient.setQueryData(['alert-detail', alert.id], updated)
      queryClient.invalidateQueries({ queryKey: ['alerts-list'] })
      queryClient.invalidateQueries({ queryKey: ['operations'] })
      setMessage({ tone: 'success', text: 'Alert status updated.' })
    },
    onError: () => {
      // No version/ETag exists on Alert to detect a stale read (see
      // report) -- the safest available response is to discard the
      // locally-assumed status and re-fetch the server-confirmed one.
      queryClient.invalidateQueries({ queryKey: ['alert-detail', alert.id] })
      setMessage({ tone: 'error', text: 'Alert status could not be updated.' })
    },
    onSettled: () => {
      setPendingStatus(null)
    },
  })

  const availableActions = getAvailableAlertStatusActions(alert.status)

  return (
    <>
      <CardHeader title="Analyst Decision" subtitle="Update the alert status as your investigation progresses." />

      <div className="px-5">
        <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Current Status</p>
        <div className="mt-1.5">
          <Badge tone={STATUS_TONE[alert.status]} dot>
            {alert.status}
          </Badge>
        </div>
      </div>

      <div className="mt-4 px-5 pb-5">
        <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Available Analyst Actions</p>
        {availableActions.length === 0 ? (
          <p className="mt-1.5 text-xs text-fg-subtle">This alert is resolved. No further status changes are available.</p>
        ) : (
          <div className="mt-2 flex flex-wrap gap-2">
            {availableActions.map((next) => (
              <Button
                key={next}
                type="button"
                variant="secondary"
                size="sm"
                disabled={mutation.isPending}
                onClick={() => mutation.mutate(next)}
              >
                {mutation.isPending && pendingStatus === next ? 'Updating…' : ALERT_STATUS_ACTION_LABEL[next]}
              </Button>
            ))}
          </div>
        )}

        <div aria-live="polite" className="mt-2 min-h-[1rem] text-xs">
          {mutation.isPending && <span className="text-fg-subtle">Updating alert status…</span>}
          {!mutation.isPending && message && (
            <span className={message.tone === 'success' ? 'text-success' : 'text-danger'}>{message.text}</span>
          )}
        </div>
      </div>
    </>
  )
}
