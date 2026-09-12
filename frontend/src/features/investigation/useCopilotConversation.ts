import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { askCopilot, askCopilotFollowUp } from '@/services/alertsService'
import type { CopilotAssessment, CopilotFollowUpResponse, CopilotMessage } from '@/types/api'

export type ConversationTurn =
  | { kind: 'initial'; question: string; assessment: CopilotAssessment }
  | { kind: 'followUp'; question: string; response: CopilotFollowUpResponse }

/** Drives POST /alerts/{id}/copilot (initial) and the existing, previously
 * unwired POST /alerts/{id}/copilot/follow-up. Conversation state lives
 * only in this component's memory for the current page view -- AMNIX
 * does not persist follow-up history server-side (see
 * CopilotFollowUpRequest's own docstring), so this hook does not either.
 * Nothing here is called until the analyst explicitly asks a question
 * (brief Phase 5: "Copilot should be called only after explicit analyst
 * interaction").
 *
 * `history` sent on every follow-up call is built exclusively from
 * real turns already rendered on screen -- the analyst's own questions
 * and the backend's own returned text (the initial assessment's
 * `summary`, or a prior follow-up's `answer`) -- mapped 1:1 to
 * user/assistant roles. Nothing is fabricated and no system-level
 * content is ever included, matching CopilotMessage's role restriction.
 */
export function useCopilotConversation(alertId: string) {
  const [turns, setTurns] = useState<ConversationTurn[]>([])
  const [lastQuestion, setLastQuestion] = useState<string | null>(null)

  const initialMutation = useMutation({
    mutationFn: (question: string) => askCopilot(alertId, question),
    onSuccess: (response, question) => {
      setTurns((prev) => [...prev, { kind: 'initial', question, assessment: response.assessment }])
    },
  })

  const followUpMutation = useMutation({
    mutationFn: (question: string) => askCopilotFollowUp(alertId, { question, history: buildHistory(turns) }),
    onSuccess: (response, question) => {
      setTurns((prev) => [...prev, { kind: 'followUp', question, response }])
    },
  })

  const hasAsked = turns.length > 0

  function ask(question: string) {
    setLastQuestion(question)
    if (!hasAsked) {
      initialMutation.mutate(question)
    } else {
      followUpMutation.mutate(question)
    }
  }

  return {
    turns,
    hasAsked,
    isPending: initialMutation.isPending || followUpMutation.isPending,
    error: initialMutation.error ?? followUpMutation.error,
    retry: () => {
      if (lastQuestion) ask(lastQuestion)
    },
    ask,
  }
}

function buildHistory(turns: ConversationTurn[]): CopilotMessage[] {
  const history: CopilotMessage[] = []
  for (const turn of turns) {
    history.push({ role: 'user', content: turn.question })
    history.push({
      role: 'assistant',
      content: turn.kind === 'initial' ? turn.assessment.summary : turn.response.answer,
    })
  }
  return history
}
