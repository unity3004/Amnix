import { useState } from 'react'
import { Bot, Send, Loader2 } from 'lucide-react'
import { CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ui/ErrorState'
import { EmptyState } from '@/components/ui/EmptyState'
import { ApiError } from '@/services/httpClient'
import { EvidenceRefLinks } from './EvidenceRefLinks'
import { QuestionStarters } from './QuestionStarters'
import type { ConversationTurn } from '../useCopilotConversation'
import type { CopilotAssessment, CopilotMitreAnalysisEntry, CopilotRecommendedInvestigationAction } from '@/types/api'

const VERDICT_TONE: Record<CopilotAssessment['verdict'], 'danger' | 'warning' | 'success' | 'neutral'> = {
  likely_malicious: 'danger',
  suspicious: 'warning',
  likely_benign: 'success',
  inconclusive: 'neutral',
}

function SenderLabel({ who }: { who: 'You' | 'Copilot' }) {
  return <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-fg-subtle">{who}</p>
}

function MitreSection({ entries, eventRefMap }: { entries: CopilotMitreAnalysisEntry[]; eventRefMap: Map<string, string> }) {
  if (entries.length === 0) return null
  return (
    <div className="mt-3">
      <p className="text-[11px] uppercase tracking-wide text-fg-subtle">MITRE Context</p>
      <ul className="mt-1 flex flex-col gap-1.5">
        {entries.map((entry, i) => (
          <li key={i} className="rounded-sm bg-bg-inset px-2 py-1.5 text-xs text-fg-muted">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono font-semibold text-accent-strong">
                {entry.technique_id} — {entry.technique_name}
              </span>
              <span className="text-[10px] text-fg-subtle">confidence: {entry.confidence}</span>
            </div>
            <p className="mt-0.5">{entry.rationale}</p>
            <div className="mt-1">
              <EvidenceRefLinks refs={entry.supporting_event_refs} eventRefMap={eventRefMap} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}

function RecommendedActionsSection({
  actions,
  eventRefMap,
}: {
  actions: CopilotRecommendedInvestigationAction[]
  eventRefMap: Map<string, string>
}) {
  if (actions.length === 0) return null
  return (
    <div className="mt-3">
      <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Suggested investigation actions</p>
      <ul className="mt-1 flex flex-col gap-1.5">
        {actions.map((action) => (
          <li key={action.action_id} className="text-xs text-fg-muted">
            <span className="font-medium text-fg">{action.label}</span> — {action.description}
            <div className="mt-0.5">
              <EvidenceRefLinks refs={action.supporting_event_refs} eventRefMap={eventRefMap} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}

function InitialTurn({
  question,
  assessment,
  eventRefMap,
}: {
  question: string
  assessment: CopilotAssessment
  eventRefMap: Map<string, string>
}) {
  return (
    <div className="flex flex-col gap-3">
      <div>
        <SenderLabel who="You" />
        <p className="rounded-md bg-bg-inset px-3 py-2 text-sm text-fg-muted">{question}</p>
      </div>
      <div>
        <SenderLabel who="Copilot" />
        <div className="rounded-md border border-border-strong bg-surface-elevated p-3">
          <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Assessment</p>
          <div className="mt-1.5 flex items-center gap-2">
            <Badge tone={VERDICT_TONE[assessment.verdict]}>{assessment.verdict.replace(/_/g, ' ')}</Badge>
            <span className="text-xs text-fg-subtle">confidence: {assessment.confidence}</span>
          </div>
          <p className="mt-1 text-[11px] italic text-fg-subtle">
            Copilot&apos;s assessment based on the supplied evidence — not a confirmed fact.
          </p>
          <p className="mt-2 text-sm text-fg">{assessment.summary}</p>

          {assessment.key_findings.length > 0 && (
            <div className="mt-3">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Key findings</p>
              <ul className="mt-1 flex flex-col gap-1">
                {assessment.key_findings.map((finding, i) => (
                  <li key={i} className="text-xs text-fg-muted">
                    <span className="mr-1.5 font-mono uppercase text-fg-subtle">[{finding.type}]</span>
                    {finding.statement}
                    <div className="mt-0.5">
                      <EvidenceRefLinks refs={finding.supporting_event_refs} eventRefMap={eventRefMap} />
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {assessment.evidence.length > 0 && (
            <div className="mt-3">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Evidence</p>
              <ul className="mt-1 flex flex-col gap-1">
                {assessment.evidence.map((item, i) => (
                  <li key={i} className="text-xs text-fg-muted">
                    <span className="font-mono text-fg-subtle">{item.field}:</span> {item.value} — {item.explanation}
                    {item.event_ref && (
                      <div className="mt-0.5">
                        <EvidenceRefLinks refs={[item.event_ref]} eventRefMap={eventRefMap} />
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <MitreSection entries={assessment.mitre_analysis} eventRefMap={eventRefMap} />

          {assessment.recommended_next_steps.length > 0 && (
            <div className="mt-3">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Recommended next steps</p>
              <ul className="mt-1 list-inside list-disc text-xs text-fg-muted">
                {assessment.recommended_next_steps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ul>
            </div>
          )}

          <RecommendedActionsSection actions={assessment.recommended_actions} eventRefMap={eventRefMap} />

          {assessment.limitations.length > 0 && (
            <div className="mt-3 border-t border-border pt-2">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Limitations</p>
              <ul className="mt-1 list-inside list-disc text-xs text-fg-subtle">
                {assessment.limitations.map((limitation, i) => (
                  <li key={i}>{limitation}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function FollowUpTurn({
  question,
  turn,
  eventRefMap,
}: {
  question: string
  turn: ConversationTurn & { kind: 'followUp' }
  eventRefMap: Map<string, string>
}) {
  const { answer, supporting_event_refs, mitre_refs, recommended_actions, limitations } = turn.response
  return (
    <div className="flex flex-col gap-3">
      <div>
        <SenderLabel who="You" />
        <p className="rounded-md bg-bg-inset px-3 py-2 text-sm text-fg-muted">{question}</p>
      </div>
      <div>
        <SenderLabel who="Copilot" />
        <div className="rounded-md border border-border-strong bg-surface-elevated p-3">
          <p className="text-sm text-fg">{answer}</p>

          {supporting_event_refs.length > 0 && (
            <div className="mt-3">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Evidence</p>
              <div className="mt-1">
                <EvidenceRefLinks refs={supporting_event_refs} eventRefMap={eventRefMap} />
              </div>
            </div>
          )}

          <MitreSection entries={mitre_refs} eventRefMap={eventRefMap} />
          <RecommendedActionsSection actions={recommended_actions} eventRefMap={eventRefMap} />

          {limitations.length > 0 && (
            <div className="mt-3 border-t border-border pt-2">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Limitations</p>
              <ul className="mt-1 list-inside list-disc text-xs text-fg-subtle">
                {limitations.map((limitation, i) => (
                  <li key={i}>{limitation}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

/** Section F: the Copilot reasoning panel. Renders exclusively from
 * real POST /alerts/{id}/copilot and POST /alerts/{id}/copilot/follow-up
 * responses (see useCopilotConversation) -- verdict, confidence,
 * summary, evidence, MITRE analysis, limitations, and recommended
 * (investigation-only) actions all come directly off the backend
 * response. Nothing here is fabricated by the frontend: there is no
 * client-side code path that invents a verdict, confidence value,
 * technique id, evidence reference, or action.
 *
 * Step 12F: evidence/MITRE/action `event_ref`/`supporting_event_refs`
 * citations are rendered as links into the existing EventDetailPage via
 * `eventRefMap` (see eventRefMap.ts) -- a purely client-side lookup
 * built from data the Investigation Workspace already fetched, so this
 * never issues a per-reference request.
 *
 * Follow-up questions reuse the existing, previously-unwired
 * POST /alerts/{id}/copilot/follow-up endpoint; conversation history
 * lives only in this page's memory (component state), matching the
 * backend's own "history is not persisted" contract.
 */
export function CopilotConversationPanel({
  turns,
  hasAsked,
  isPending,
  error,
  eventRefMap,
  onAsk,
  onRetry,
}: {
  turns: ConversationTurn[]
  hasAsked: boolean
  isPending: boolean
  error: unknown
  eventRefMap: Map<string, string>
  onAsk: (question: string) => void
  onRetry: () => void
}) {
  const [question, setQuestion] = useState('')

  function submit() {
    if (!question.trim() || isPending) return
    onAsk(question.trim())
    setQuestion('')
  }

  return (
    <div className="flex h-full flex-col">
      <CardHeader title="AI Copilot" subtitle="AI-assisted reasoning, scoped to this alert" />
      <p className="px-5 pb-3 text-[11px] text-fg-subtle">
        Copilot provides advisory analysis based on the investigation evidence available to AMNIX. Validate
        conclusions against the underlying evidence before taking action.
      </p>

      <div className="flex-1 overflow-y-auto px-5">
        {turns.length === 0 && !isPending && !error && (
          <EmptyState
            icon={Bot}
            title="Ask Copilot about this investigation."
            description="Copilot reasons only over this alert's real evidence -- nothing is asked automatically."
          />
        )}

        <div className="flex flex-col gap-4 pb-2">
          {turns.map((turn, i) =>
            turn.kind === 'initial' ? (
              <InitialTurn key={i} question={turn.question} assessment={turn.assessment} eventRefMap={eventRefMap} />
            ) : (
              <FollowUpTurn key={i} question={turn.question} turn={turn} eventRefMap={eventRefMap} />
            ),
          )}
        </div>

        {isPending && (
          <div className="flex items-center gap-2 pb-4 text-xs text-fg-subtle" role="status">
            <Loader2 className="size-3.5 animate-spin" strokeWidth={2} aria-hidden="true" />
            Analyzing investigation…
          </div>
        )}

        {error !== null && error !== undefined && (
          <div className="pb-4">
            <ErrorState
              title="Copilot is unavailable"
              message={error instanceof ApiError ? error.message : 'Unable to reach the AMNIX backend.'}
              onRetry={onRetry}
            />
          </div>
        )}
      </div>

      <div className="border-t border-border px-5 py-4">
        <div className="mb-2">
          <QuestionStarters onSelect={setQuestion} disabled={isPending} />
        </div>
        <label htmlFor="copilot-question" className="mb-1.5 block text-xs font-medium text-fg-muted">
          {hasAsked ? 'Ask a follow-up question' : 'Ask Copilot about this investigation'}
        </label>
        <textarea
          id="copilot-question"
          rows={2}
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder={hasAsked ? 'Ask a follow-up question…' : 'What happened here? Is this likely malicious?'}
          className="w-full resize-none rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg placeholder:text-fg-subtle focus:border-accent/50 focus:outline-none"
        />
        <div className="mt-2 flex justify-end">
          <Button variant="primary" size="sm" disabled={!question.trim() || isPending} onClick={submit}>
            <Send className="size-3.5" strokeWidth={2} aria-hidden="true" />
            {isPending ? 'Analyzing…' : hasAsked ? 'Ask follow-up' : 'Ask'}
          </Button>
        </div>
      </div>
    </div>
  )
}
