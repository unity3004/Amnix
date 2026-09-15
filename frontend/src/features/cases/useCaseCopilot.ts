import { useMutation } from '@tanstack/react-query'
import { askCaseCopilot } from '@/services/casesService'
import type { CaseCopilotResponse } from '@/types/api'

/** Drives POST /cases/{id}/copilot (Step 13D) -- the one and only place
 * in AMNIX that calls this endpoint. Nothing here fires until the
 * analyst explicitly clicks "Generate Investigation Brief" (see
 * CaseCopilotPanel, the only caller of `generate`): no automatic call on
 * page load, no polling, no per-alert/per-note automatic trigger.
 *
 * `status` mirrors the panel's own READY/GENERATING/SUCCESS/FAILURE
 * states directly off React Query's own mutation status ('idle' ->
 * READY, 'pending' -> GENERATING, 'success' -> SUCCESS, 'error' ->
 * FAILURE) -- there is no separate, hand-rolled state machine that could
 * drift from what actually happened on the wire.
 */
export function useCaseCopilot(caseId: string) {
  const mutation = useMutation({
    mutationFn: (variables: { question: string; focusedAlertId: string | null }) =>
      askCaseCopilot(caseId, { question: variables.question, focused_alert_id: variables.focusedAlertId }),
  })

  return {
    generate: (question: string, focusedAlertId: string | null) => mutation.mutate({ question, focusedAlertId }),
    status: mutation.status,
    data: mutation.data as CaseCopilotResponse | undefined,
    error: mutation.error,
    reset: mutation.reset,
  }
}
