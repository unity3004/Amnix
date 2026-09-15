import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Bot, Loader2, Sparkles } from 'lucide-react'
import { CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { ApiError } from '@/services/httpClient'
import { useInvestigation } from '@/features/investigation/useInvestigation'
import { buildEventRefMap } from '@/features/investigation/eventRefMap'
import { buildAlertRefMap } from '../caseAlertRefMap'
import { useCaseCopilot } from '../useCaseCopilot'
import type {
  AlertRead,
  CaseEvidenceItem,
  CaseInvestigationBrief,
  CaseKeyFinding,
  CopilotMitreAnalysisEntry,
} from '@/types/api'

function RefLink({ label, id, to }: { label: string; id: string | undefined; to: (id: string) => string }) {
  return id ? (
    <Link
      to={to(id)}
      className="rounded-sm bg-bg-inset px-1.5 py-0.5 font-mono text-[10px] text-accent-strong transition-colors duration-fast hover:bg-accent-dim"
      title="Open the cited resource"
    >
      {label}
    </Link>
  ) : (
    <span className="rounded-sm bg-bg-inset px-1.5 py-0.5 font-mono text-[10px] text-fg-subtle" title="Reference could not be resolved">
      {label}
    </span>
  )
}

function RefLinks({
  alertRefs = [],
  eventRefs = [],
  alertRefMap,
  eventRefMap,
}: {
  alertRefs?: string[]
  eventRefs?: string[]
  alertRefMap: Map<string, string>
  eventRefMap: Map<string, string>
}) {
  if (alertRefs.length === 0 && eventRefs.length === 0) return null
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {alertRefs.map((ref) => (
        <RefLink key={ref} label={ref} id={alertRefMap.get(ref)} to={(id) => `/alerts/${id}`} />
      ))}
      {eventRefs.map((ref) => (
        <RefLink key={ref} label={ref} id={eventRefMap.get(ref)} to={(id) => `/events/${id}`} />
      ))}
    </span>
  )
}

function KeyFindingsSection({
  findings,
  alertRefMap,
  eventRefMap,
}: {
  findings: CaseKeyFinding[]
  alertRefMap: Map<string, string>
  eventRefMap: Map<string, string>
}) {
  if (findings.length === 0) return null
  return (
    <div className="mt-3">
      <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Key Findings</p>
      <ul className="mt-1 flex flex-col gap-1">
        {findings.map((finding, i) => (
          <li key={i} className="text-xs text-fg-muted">
            <span className="mr-1.5 font-mono uppercase text-fg-subtle">[{finding.type}]</span>
            {finding.statement}
            <div className="mt-0.5">
              <RefLinks
                alertRefs={finding.supporting_alert_refs}
                eventRefs={finding.supporting_event_refs}
                alertRefMap={alertRefMap}
                eventRefMap={eventRefMap}
              />
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}

function SupportingEvidenceSection({
  evidence,
  alertRefMap,
  eventRefMap,
}: {
  evidence: CaseEvidenceItem[]
  alertRefMap: Map<string, string>
  eventRefMap: Map<string, string>
}) {
  if (evidence.length === 0) return null
  return (
    <div className="mt-3">
      <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Supporting Evidence</p>
      <ul className="mt-1 flex flex-col gap-1">
        {evidence.map((item, i) => (
          <li key={i} className="text-xs text-fg-muted">
            <span className="font-mono text-fg-subtle">{item.field}:</span> {item.value} — {item.explanation}
            <div className="mt-0.5">
              <RefLinks
                alertRefs={item.alert_ref ? [item.alert_ref] : []}
                eventRefs={item.event_ref ? [item.event_ref] : []}
                alertRefMap={alertRefMap}
                eventRefMap={eventRefMap}
              />
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
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
              <RefLinks eventRefs={entry.supporting_event_refs} alertRefMap={new Map()} eventRefMap={eventRefMap} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}

function InvestigationBrief({
  brief,
  alertRefMap,
  eventRefMap,
}: {
  brief: CaseInvestigationBrief
  alertRefMap: Map<string, string>
  eventRefMap: Map<string, string>
}) {
  return (
    <div className="rounded-md border border-accent/30 bg-surface-elevated p-3">
      <div className="flex items-center gap-2">
        <Sparkles className="size-3.5 text-accent-strong" strokeWidth={1.75} aria-hidden="true" />
        <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Generated Brief</p>
      </div>
      <p className="mt-1 text-[11px] italic text-fg-subtle">
        AI-generated, advisory only. AMNIX does not act on this automatically -- verify against the real evidence above
        before taking any action.
      </p>
      <p className="mt-2 text-sm text-fg">{brief.summary}</p>

      <KeyFindingsSection findings={brief.key_findings} alertRefMap={alertRefMap} eventRefMap={eventRefMap} />
      <SupportingEvidenceSection evidence={brief.supporting_evidence} alertRefMap={alertRefMap} eventRefMap={eventRefMap} />
      <MitreSection entries={brief.mitre_analysis} eventRefMap={eventRefMap} />

      <div className="mt-3">
        <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Timeline Summary</p>
        <p className="mt-1 text-xs text-fg-muted">{brief.timeline_summary}</p>
      </div>

      {brief.uncertainties.length > 0 && (
        <div className="mt-3 border-t border-border pt-2">
          <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Uncertainties</p>
          <ul className="mt-1 list-inside list-disc text-xs text-fg-subtle">
            {brief.uncertainties.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
        </div>
      )}

      {brief.recommended_next_steps.length > 0 && (
        <div className="mt-3 border-t border-border pt-2">
          <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Recommended Next Steps</p>
          <p className="mt-0.5 text-[10px] italic text-fg-subtle">Analyst guidance only -- no actions are executed automatically.</p>
          <ul className="mt-1 list-inside list-disc text-xs text-fg-muted">
            {brief.recommended_next_steps.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

/** Step 13D: the Case-scoped "Generate Investigation Brief" panel --
 * explicit, analyst-triggered only (see useCaseCopilot: nothing here
 * calls POST /cases/{id}/copilot until the button below is clicked).
 * Deliberately separate from CaseSummaryPanel (Step 13C, deterministic,
 * application-generated): this panel is visually and semantically marked
 * as AI-generated advisory output (accent border, Sparkles icon, and a
 * mandatory trust notice on every rendered brief), never the reverse.
 *
 * READY/GENERATING/SUCCESS/FAILURE map directly to useCaseCopilot's own
 * `status` ('idle'/'pending'/'success'/'error') -- there is no separate
 * loading state that could show fabricated content while a request is
 * in flight.
 *
 * The optional focused-alert selector mirrors CaseTimelinePanel's own
 * pattern exactly: GET /alerts/{id}/investigation is fetched (via
 * useInvestigation) only when the analyst picks one of this case's own
 * REAL linked alerts, purely to resolve this brief's `evt-N` references
 * into real Event Detail links -- never to send that telemetry back to
 * the server (the server reconstructs its own copy from `case_id` +
 * `focused_alert_id` alone; see CaseCopilotQuestionRequest's own
 * docstring). Never fetched automatically, never looped across every
 * linked alert.
 *
 * Generating a brief never creates a Case Note, never links/unlinks an
 * alert, and never changes case status/priority/owner -- there is no
 * code path here that calls any of those endpoints.
 */
export function CaseCopilotPanel({ caseId, alerts }: { caseId: string; alerts: AlertRead[] }) {
  const [question, setQuestion] = useState('')
  const [focusedAlertId, setFocusedAlertId] = useState<string | undefined>(undefined)
  const { generate, status, data, error, reset } = useCaseCopilot(caseId)
  const investigationQuery = useInvestigation(focusedAlertId)

  const alertRefMap = buildAlertRefMap(alerts)
  const eventRefMap = investigationQuery.data ? buildEventRefMap(investigationQuery.data.timeline) : new Map<string, string>()

  const isGenerating = status === 'pending'

  function submit() {
    if (!question.trim() || isGenerating) return
    generate(question.trim(), focusedAlertId ?? null)
  }

  return (
    <div className="flex flex-col">
      <CardHeader title="AI Investigation Brief" subtitle="AI-assisted reasoning, scoped to this case -- generated only when you ask." />

      <div className="px-5 pb-4">
        {alerts.length > 0 && (
          <div className="mb-3">
            <label htmlFor="case-copilot-alert-select" className="text-[11px] uppercase tracking-wide text-fg-subtle">
              Focus on alert (optional)
            </label>
            <select
              id="case-copilot-alert-select"
              value={focusedAlertId ?? ''}
              onChange={(e) => setFocusedAlertId(e.target.value || undefined)}
              disabled={isGenerating}
              className="mt-1.5 h-9 w-full rounded-md border border-border bg-surface px-2 text-sm text-fg focus:border-accent/50 focus:outline-none sm:w-auto"
            >
              <option value="">— none selected —</option>
              {alerts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.title} ({a.severity})
                </option>
              ))}
            </select>
          </div>
        )}

        <label htmlFor="case-copilot-question" className="mb-1.5 block text-xs font-medium text-fg-muted">
          Ask about this case
        </label>
        <textarea
          id="case-copilot-question"
          rows={2}
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          disabled={isGenerating}
          placeholder="What happened across these linked alerts? What should I investigate next?"
          className="w-full resize-none rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg placeholder:text-fg-subtle focus:border-accent/50 focus:outline-none"
        />
        <div className="mt-2 flex justify-end">
          <Button variant="primary" size="sm" disabled={!question.trim() || isGenerating} onClick={submit}>
            <Sparkles className="size-3.5" strokeWidth={2} aria-hidden="true" />
            {isGenerating ? 'Generating…' : 'Generate Investigation Brief'}
          </Button>
        </div>

        <div className="mt-4">
          {status === 'idle' && (
            <EmptyState
              icon={Bot}
              title="No brief generated yet."
              description="Ask a question and click Generate Investigation Brief -- AMNIX never calls the AI layer automatically."
            />
          )}

          {isGenerating && (
            <div className="flex items-center gap-2 text-xs text-fg-subtle" role="status">
              <Loader2 className="size-3.5 animate-spin" strokeWidth={2} aria-hidden="true" />
              Generating investigation brief…
            </div>
          )}

          {status === 'error' && (
            <ErrorState
              title="Investigation Brief is unavailable"
              message={error instanceof ApiError ? error.message : 'Unable to reach the AMNIX backend.'}
              onRetry={() => submit()}
            />
          )}

          {status === 'success' && data && (
            <InvestigationBrief brief={data.brief} alertRefMap={alertRefMap} eventRefMap={eventRefMap} />
          )}
        </div>

        {status !== 'idle' && (
          <div className="mt-3 flex justify-end">
            <Button variant="ghost" size="sm" onClick={() => reset()}>
              Clear
            </Button>
          </div>
        )}
      </div>
    </div>
  )
}
