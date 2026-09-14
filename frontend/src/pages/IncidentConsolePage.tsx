import { useParams } from 'react-router-dom'
import { Card } from '@/components/ui/Card'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { CaseNotesPanel } from '@/features/cases/components/CaseNotesPanel'
import { useIncidentConsole } from '@/features/console/useIncidentConsole'
import { IncidentHeader } from '@/features/console/components/IncidentHeader'
import { IncidentNavRail } from '@/features/console/components/IncidentNavRail'
import { OverviewPanel } from '@/features/console/components/OverviewPanel'
import { IncidentTimelinePanel } from '@/features/console/components/IncidentTimelinePanel'
import { EvidencePanel } from '@/features/console/components/EvidencePanel'
import { AlertsPanel } from '@/features/console/components/AlertsPanel'
import { MitreCoveragePanel } from '@/features/console/components/MitreCoveragePanel'
import { DetectionRulesPanel } from '@/features/console/components/DetectionRulesPanel'
import { CopilotSummaryPanel } from '@/features/console/components/CopilotSummaryPanel'
import { IncidentAuditPanel } from '@/features/console/components/IncidentAuditPanel'
import { IncidentHealthPanel } from '@/features/console/components/IncidentHealthPanel'
import { InvestigationProgressPanel } from '@/features/console/components/InvestigationProgressPanel'
import { RecommendationsPanel } from '@/features/console/components/RecommendationsPanel'
import { CommandCenterSidebar } from '@/features/console/components/CommandCenterSidebar'
import type { LiveQueryState } from '@/lib/liveRefresh'

/** AMNIX Incident Response Console (Step 12W) -- the analyst's
 * operational "war room" for one Case. Orchestrates existing modules
 * (Case, Alert, Investigation, Copilot audit, MITRE/rule registries);
 * introduces no new backend endpoint and duplicates no evidence store.
 * See useIncidentConsole.ts for the full network/caching contract this
 * page honors (always: case/alerts/notes/audit; on-demand, scoped to
 * one focused alert only: investigation/Copilot audits).
 */
export function IncidentConsolePage() {
  const { caseId } = useParams<{ caseId: string }>()
  const incident = useIncidentConsole(caseId)

  if (incident.isCasePending) {
    return (
      <div className="mx-auto max-w-[1000px] px-6 py-6">
        <Card className="p-6">
          <Skeleton className="h-6 w-64" />
          <Skeleton className="mt-3 h-4 w-40" />
          <Skeleton className="mt-6 h-32 w-full" />
        </Card>
      </div>
    )
  }

  if (incident.isCaseError || !incident.caseItem) {
    return (
      <div className="mx-auto max-w-[1000px] px-6 py-6">
        <Card>
          <ErrorState title="Unable to retrieve this case" onRetry={() => incident.refresh()} />
        </Card>
      </div>
    )
  }

  const caseItem = incident.caseItem
  const liveState: LiveQueryState = incident.isCaseError ? 'error' : 'live'

  return (
    <div className="flex flex-col">
      <IncidentHeader
        caseItem={caseItem}
        liveState={liveState}
        lastSuccessfulRefreshAt={incident.lastSuccessfulRefreshAt}
        isRefreshing={incident.isRefreshing}
        onRefresh={incident.refresh}
      />

      <div className="mx-auto grid w-full max-w-[1600px] grid-cols-1 gap-6 px-6 py-6 lg:grid-cols-[180px_1fr_280px]">
        <div className="hidden lg:block">
          <IncidentNavRail />
        </div>

        <main aria-label="Incident workspace" className="flex flex-col gap-4">
          <OverviewPanel
            caseItem={caseItem}
            detectionSnapshot={incident.detectionSnapshot}
            focusedAlertTitle={incident.focusedAlert?.title ?? null}
            investigationLoaded={Boolean(incident.investigation)}
            timelineEventCount={incident.investigation?.timeline.length ?? 0}
            hasFindings={Boolean(
              incident.investigation &&
                (incident.investigation.entities.hostnames.length > 0 ||
                  incident.investigation.entities.usernames.length > 0 ||
                  incident.investigation.entities.source_ips.length > 0 ||
                  incident.investigation.entities.destination_ips.length > 0 ||
                  incident.investigation.entities.process_names.length > 0 ||
                  incident.investigation.entities.file_hashes.length > 0),
            )}
            hasEntities={Boolean(incident.investigation && incident.investigation.timeline.length > 0)}
          />

          <IncidentTimelinePanel
            entries={incident.timeline}
            focusedAlertLoaded={Boolean(incident.investigation)}
            caseId={caseItem.id}
            caseNumber={caseItem.case_number}
          />

          <EvidencePanel
            alerts={incident.alerts}
            focusedAlert={incident.focusedAlert}
            focusedAlertId={incident.focusedAlertId}
            onFocusAlert={incident.setFocusedAlertId}
            investigation={incident.investigation}
            isInvestigationPending={incident.isInvestigationPending}
            isInvestigationError={incident.isInvestigationError}
          />

          <AlertsPanel caseItem={caseItem} alertsBySeverity={incident.alertsBySeverity} onFocusAlert={incident.setFocusedAlertId} />

          <MitreCoveragePanel byTactic={incident.mitreByTactic} />

          <DetectionRulesPanel rules={incident.participatingRules} />

          <CopilotSummaryPanel
            caseItem={caseItem}
            focusedAlertId={incident.focusedAlertId}
            focusedAlertTitle={incident.focusedAlert?.title ?? null}
            audits={incident.copilotAudits}
            isPending={incident.isCopilotAuditsPending}
          />

          <Card id="console-notes" className="scroll-mt-20 overflow-hidden">
            <CaseNotesPanel caseId={caseItem.id} />
          </Card>

          <IncidentAuditPanel audits={incident.audits} isPending={false} />
        </main>

        <div className="flex flex-col gap-4">
          <IncidentHealthPanel health={incident.incidentHealth} />
          <InvestigationProgressPanel items={incident.investigationProgress} />
          <RecommendationsPanel recommendations={incident.recommendations} />
          <CommandCenterSidebar
            caseItem={caseItem}
            focusedAlertId={incident.focusedAlertId}
            focusedAlertRuleId={incident.focusedAlert?.rule_id}
            focusedAlertFirstEventId={incident.focusedAlert?.source_event_ids[0]}
          />
        </div>
      </div>
    </div>
  )
}
