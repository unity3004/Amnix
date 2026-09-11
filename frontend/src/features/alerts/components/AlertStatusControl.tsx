import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { updateAlertStatus } from '@/services/alertsService'
import { Button } from '@/components/ui/Button'
import { ApiError } from '@/services/httpClient'
import { ALERT_STATUS_VALUES } from '../types'
import type { AlertRead, AlertStatus } from '@/types/api'

/** Uses only PATCH /alerts/{id}/status and the existing AlertStatus
 * vocabulary -- no new remediation actions, no client-side lifecycle
 * validation (the backend's assert_valid_transition() is the one
 * source of truth for which transitions are allowed; an invalid one
 * simply comes back as a safe 409, shown here rather than duplicated).
 */
export function AlertStatusControl({ alert }: { alert: AlertRead }) {
  const [pending, setPending] = useState<AlertStatus>(alert.status)
  const [error, setError] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const mutation = useMutation({
    mutationFn: (status: AlertStatus) => updateAlertStatus(alert.id, status),
    onSuccess: () => {
      setError(null)
      queryClient.invalidateQueries({ queryKey: ['alert-detail', alert.id] })
      queryClient.invalidateQueries({ queryKey: ['alerts-list'] })
    },
    onError: (err) => {
      setError(err instanceof ApiError ? err.message : 'Unable to update alert status.')
    },
  })

  return (
    <div className="flex items-center gap-2">
      <select
        value={pending}
        onChange={(e) => setPending(e.target.value as AlertStatus)}
        className="h-8 rounded-md border border-border bg-surface px-2 text-xs text-fg-muted focus:border-accent/50 focus:outline-none"
        aria-label="Change alert status"
      >
        {ALERT_STATUS_VALUES.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>
      <Button variant="secondary" size="sm" disabled={pending === alert.status || mutation.isPending} onClick={() => mutation.mutate(pending)}>
        {mutation.isPending ? 'Updating…' : 'Change status'}
      </Button>
      {error && (
        <span role="alert" className="text-xs text-danger">
          {error}
        </span>
      )}
    </div>
  )
}
