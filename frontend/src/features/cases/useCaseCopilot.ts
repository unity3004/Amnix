import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { askCaseCopilot, askCaseCopilotFollowUp } from '@/services/casesService'
import type { CaseCopilotFollowUpResponse, CaseInvestigationBrief, CopilotMessage } from '@/types/api'

export type CaseConversationTurn =
  | { kind: 'initial'; question: string; brief: CaseInvestigationBrief }
  | { kind: 'followUp'; question: string; response: CaseCopilotFollowUpResponse }

/** Drives POST /cases/{id}/copilot (Step 13D, "Generate Investigation
 * Brief") and POST /cases/{id}/copilot/follow-up (Step 13E) -- the one
 * and only place in AMNIX that calls either endpoint. Nothing here fires
 * until the analyst explicitly calls `generate` or `ask` (see
 * CaseCopilotPanel, the only caller): no automatic call on page load, no
 * polling, no per-alert/per-note automatic trigger.
 *
 * Conversation state (`turns`) lives only in this hook's memory for the
 * current page view -- AMNIX does not persist follow-up history
 * server-side (see CaseCopilotFollowUpRequest's own docstring), so this
 * hook does not either. `history` sent on every follow-up call is built
 * exclusively from real turns already rendered on screen -- the
 * analyst's own questions and the backend's own returned text (the
 * initial brief's `summary`, or a prior follow-up's `answer`) -- mapped
 * 1:1 to user/assistant roles. Nothing is fabricated.
 *
 * A follow-up is only ever dispatched after a successful initial brief
 * (`turns.length > 0`): the follow-up endpoint accepts no
 * `focused_alert_id` and always rebuilds the case context fresh, so
 * there is no dependency on the initial brief's own request beyond
 * "a conversation has started."
 */
export function useCaseCopilot(caseId: string) {
  const [turns, setTurns] = useState<CaseConversationTurn[]>([])
  const [lastQuestion, setLastQuestion] = useState<string | null>(null)
  const [lastFocusedAlertId, setLastFocusedAlertId] = useState<string | null>(null)

  const generateMutation = useMutation({
    mutationFn: (variables: { question: string; focusedAlertId: string | null }) =>
      askCaseCopilot(caseId, { question: variables.question, focused_alert_id: variables.focusedAlertId }),
    onSuccess: (response, variables) => {
      setTurns((prev) => [...prev, { kind: 'initial', question: variables.question, brief: response.brief }])
    },
  })

  const followUpMutation = useMutation({
    mutationFn: (question: string) => askCaseCopilotFollowUp(caseId, { question, history: buildHistory(turns) }),
    onSuccess: (response, question) => {
      setTurns((prev) => [...prev, { kind: 'followUp', question, response }])
    },
  })

  const hasGenerated = turns.length > 0

  function generate(question: string, focusedAlertId: string | null) {
    setLastQuestion(question)
    setLastFocusedAlertId(focusedAlertId)
    generateMutation.mutate({ question, focusedAlertId })
  }

  function ask(question: string) {
    setLastQuestion(question)
    followUpMutation.mutate(question)
  }

  return {
    turns,
    hasGenerated,
    generate,
    ask,
    isGenerating: generateMutation.isPending,
    isAsking: followUpMutation.isPending,
    generateError: generateMutation.error,
    followUpError: followUpMutation.error,
    retryGenerate: () => {
      if (lastQuestion !== null) generate(lastQuestion, lastFocusedAlertId)
    },
    retryAsk: () => {
      if (lastQuestion !== null) ask(lastQuestion)
    },
    reset: () => {
      generateMutation.reset()
      followUpMutation.reset()
      setTurns([])
    },
  }
}

function buildHistory(turns: CaseConversationTurn[]): CopilotMessage[] {
  const history: CopilotMessage[] = []
  for (const turn of turns) {
    history.push({ role: 'user', content: turn.question })
    history.push({
      role: 'assistant',
      content: turn.kind === 'initial' ? turn.brief.summary : turn.response.answer,
    })
  }
  return history
}
