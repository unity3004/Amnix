import { useMemo } from 'react'
import { useParams } from 'react-router-dom'
import { Card } from '@/components/ui/Card'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { useAlertDetail } from '@/features/alerts/useAlertDetail'
import { AlertStatusControl } from '@/features/alerts/components/AlertStatusControl'
import { useInvestigation } from '@/features/investigation/useInvestigation'
import { useCopilotConversation } from '@/features/investigation/useCopilotConversation'
import { InvestigationHeader } from '@/features/investigation/components/InvestigationHeader'
import { AlertSummaryPanel } from '@/features/investigation/components/AlertSummaryPanel'
import { EvidencePanel } from '@/features/investigation/components/EvidencePanel'
import { FindingsPanel } from '@/features/investigation/components/FindingsPanel'
import { MitrePanel } from '@/features/investigation/components/MitrePanel'
import { InvestigationTimeline } from '@/features/investigation/components/InvestigationTimeline'
import { CopilotConversationPanel } from '@/features/investigation/components/CopilotConversationPanel'
import { buildEventRefMap } from '@/features/investigation/eventRefMap'
import type { CopilotMitreAnalysisEntry } from '@/types/api'

/** AMNIX SOC Analyst Investigation Workspace (Step 12E).
 *
 * Data sources, each fetched exactly once when this page opens (no
 * polling, no per-row fetching, no N+1):
 *   - GET /alerts/{id}                  -- useAlertDetail (existing hook)
 *   - GET /alerts/{id}/investigation     -- useInvestigation (existing service fn)
 *   - POST /alerts/{id}/copilot          -- only on explicit "Ask"
 *   - POST /alerts/{id}/copilot/follow-up -- only on explicit follow-up "Ask"
 *
 * The investigation response already embeds every related event's full
 * field set (InvestigationContext.timeline), so Evidence/Findings/
 * Timeline all render from that single response -- zero additional
 * requests per event. Status changes reuse the existing
 * AlertStatusControl unmodified. No remediation/execution action is
 * introduced anywhere on this page.
 */
export function InvestigationWorkspacePage() {
  const { alertId } = useParams<{ alertId: string }>()

  const alertQuery = useAlertDetail(alertId)
  const investigationQuery = useInvestigation(alertId)
  const conversation = useCopilotConversation(alertId ?? '')

  const copilotMitreEntries = useMemo(() => {
    const seen = new Map<string, CopilotMitreAnalysisEntry>()
    for (const turn of conversation.turns) {
      const entries = turn.kind === 'initial' ? turn.assessment.mitre_analysis : turn.response.mitre_refs
      for (const entry of entries) seen.set(entry.technique_id, entry)
    }
    return Array.from(seen.values())
  }, [conversation.turns])

  const eventRefMap = useMemo(() => buildEventRefMap(investigationQuery.data?.timeline ?? []), [investigationQuery.data])

  if (alertQuery.isPending) {
    return (
      <div className="mx-auto max-w-[1400px] px-6 py-6">
        <Card className="p-6">
          <Skeleton className="h-6 w-72" />
          <Skeleton className="mt-3 h-4 w-48" />
          <Skeleton className="mt-6 h-32 w-full" />
        </Card>
      </div>
    )
  }

  if (alertQuery.isError || !alertQuery.data) {
    return (
      <div className="mx-auto max-w-[1400px] px-6 py-6">
        <Card>
          <ErrorState title="Unable to retrieve this alert" onRetry={() => alertQuery.refetch()} />
        </Card>
      </div>
    )
  }

  const alert = alertQuery.data
  const investigation = investigationQuery.data

  return (
    <div className="mx-auto max-w-[1600px] px-6 py-6">
      <InvestigationHeader alert={alert} />

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-[1fr_420px]">
        {/* ---- Main analyst column ---- */}
        <div className="flex flex-col gap-4">
          <Card>
            <AlertSummaryPanel
              alert={alert}
              summary={
                investigation?.summary ?? {
                  text: '',
                  event_count: alert.source_event_ids.length,
                  unique_host_count: 0,
                  unique_user_count: 0,
                  timespan_seconds: null,
                  first_event_at: null,
                  last_event_at: null,
                }
              }
            />
          </Card>

          <Card className="p-3">
            <p className="mb-2 px-2 text-[11px] uppercase tracking-wide text-fg-subtle">Analyst Actions</p>
            <div className="px-2">
              <AlertStatusControl alert={alert} />
            </div>
          </Card>

          {investigationQuery.isPending && (
            <Card className="p-6">
              <Skeleton className="h-5 w-56" />
              <Skeleton className="mt-4 h-24 w-full" />
            </Card>
          )}

          {investigationQuery.isError && (
            <Card>
              <ErrorState title="Investigation data could not be loaded" onRetry={() => investigationQuery.refetch()} />
            </Card>
          )}

          {investigation && (
            <>
              <Card className="overflow-hidden">
                <InvestigationTimeline alert={alert} timeline={investigation.timeline} />
              </Card>

              <Card className="overflow-hidden">
                <EvidencePanel timeline={investigation.timeline} />
              </Card>

              <Card>
                <FindingsPanel alert={alert} investigation={investigation} />
              </Card>
            </>
          )}

          <Card>
            <MitrePanel ruleId={alert.rule_id} copilotAnalysis={copilotMitreEntries} />
          </Card>
        </div>

        {/* ---- Copilot reasoning column ---- */}
        <Card className="flex max-h-[calc(100vh-8rem)] flex-col xl:sticky xl:top-6">
          <CopilotConversationPanel
            turns={conversation.turns}
            hasAsked={conversation.hasAsked}
            isPending={conversation.isPending}
            error={conversation.error}
            eventRefMap={eventRefMap}
            onAsk={conversation.ask}
            onRetry={conversation.retry}
          />
        </Card>
      </div>
    </div>
  )
}
