import { useEffect, useMemo, useState } from 'react'
import { useCaseDetail } from '@/features/cases/useCaseDetail'
import { useCaseAlerts } from '@/features/cases/useCaseAlerts'
import { useCaseNotes } from '@/features/cases/useCaseNotes'
import { useCaseAudit } from '@/features/cases/useCaseAudit'
import { useInvestigation } from '@/features/investigation/useInvestigation'
import { useAlertCopilotAudits } from './useAlertCopilotAudits'
import {
  buildIncidentTimeline,
  deriveDetectionSnapshot,
  deriveIncidentHealth,
  deriveInvestigationProgress,
  deriveParticipatingRules,
  deriveRecommendations,
  groupAlertsBySeverity,
  groupMitreByTactic,
} from './logic'
import { compareAlertPriority } from '@/features/alerts/priority'

/**
 * Orchestration hook for the Step 12W Incident Response Console.
 * Composes only ALREADY-EXISTING hooks -- no new backend endpoint, no
 * duplicated query. Always-fetched (matches the Console's own declared
 * Network Rules): case detail, linked alerts, notes, audit.
 * Fetched only on demand, scoped to exactly one "focused" alert: alert
 * investigation and Copilot audits -- see logic.ts's own top-of-file
 * note for why this is never looped across every linked alert.
 *
 * The focused alert defaults to the highest-priority linked alert (via
 * the existing Step 12G comparator) the first time alerts load, and
 * otherwise stays exactly where the analyst last left it -- switching
 * focus replaces the in-flight query, it never adds a second one.
 */
export function useIncidentConsole(caseId: string | undefined) {
  const caseQuery = useCaseDetail(caseId)
  const alertsQuery = useCaseAlerts(caseId)
  const notesQuery = useCaseNotes(caseId)
  const auditQuery = useCaseAudit(caseId)

  const alerts = useMemo(() => alertsQuery.data?.items ?? [], [alertsQuery.data])
  const notes = useMemo(() => notesQuery.data?.items ?? [], [notesQuery.data])
  const audits = useMemo(() => auditQuery.data?.items ?? [], [auditQuery.data])

  const [focusedAlertId, setFocusedAlertId] = useState<string | undefined>(undefined)

  // Auto-focus the highest-priority linked alert exactly once, the
  // first time this case's alerts become available -- never overrides
  // an analyst's own explicit selection afterward.
  useEffect(() => {
    if (focusedAlertId !== undefined) return
    if (alerts.length === 0) return
    const sorted = [...alerts].sort(compareAlertPriority)
    setFocusedAlertId(sorted[0].id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alerts])

  const focusedAlert = alerts.find((a) => a.id === focusedAlertId)
  const investigationQuery = useInvestigation(focusedAlertId)
  const copilotAuditsQuery = useAlertCopilotAudits(focusedAlertId)

  const focusedAlertTimeline = investigationQuery.data?.timeline
  const focusedAlertCopilotAudits = copilotAuditsQuery.data?.items

  const timeline = useMemo(
    () => buildIncidentTimeline({ audits, notes, focusedAlertTimeline, focusedAlertCopilotAudits }),
    [audits, notes, focusedAlertTimeline, focusedAlertCopilotAudits],
  )

  const detectionSnapshot = useMemo(() => deriveDetectionSnapshot(alerts), [alerts])
  const alertsBySeverity = useMemo(() => groupAlertsBySeverity(alerts), [alerts])
  const mitreByTactic = useMemo(() => groupMitreByTactic(alerts), [alerts])
  const participatingRules = useMemo(() => deriveParticipatingRules(alerts), [alerts])

  const incidentHealth = useMemo(
    () =>
      deriveIncidentHealth({
        alerts,
        notes,
        focusedAlertCopilotAudits,
        timelineEventCount: timeline.length,
      }),
    [alerts, notes, focusedAlertCopilotAudits, timeline.length],
  )

  const investigationProgress = useMemo(
    () =>
      caseQuery.data
        ? deriveInvestigationProgress({
            caseItem: caseQuery.data,
            alerts,
            notes,
            audits,
            focusedAlertTimeline,
            focusedAlertCopilotAudits,
          })
        : [],
    [caseQuery.data, alerts, notes, audits, focusedAlertTimeline, focusedAlertCopilotAudits],
  )

  const recommendations = useMemo(
    () => (caseQuery.data ? deriveRecommendations({ caseItem: caseQuery.data, alerts, notes }) : []),
    [caseQuery.data, alerts, notes],
  )

  function refreshAll() {
    caseQuery.refetch()
    alertsQuery.refetch()
    notesQuery.refetch()
    auditQuery.refetch()
    if (focusedAlertId) {
      investigationQuery.refetch()
      copilotAuditsQuery.refetch()
    }
  }

  return {
    caseItem: caseQuery.data,
    isCasePending: caseQuery.isPending,
    isCaseError: caseQuery.isError,
    alerts,
    notes,
    audits,
    focusedAlertId,
    focusedAlert,
    setFocusedAlertId,
    investigation: investigationQuery.data,
    isInvestigationPending: investigationQuery.isPending,
    isInvestigationError: investigationQuery.isError,
    copilotAudits: focusedAlertCopilotAudits,
    isCopilotAuditsPending: copilotAuditsQuery.isPending,
    timeline,
    detectionSnapshot,
    alertsBySeverity,
    mitreByTactic,
    participatingRules,
    incidentHealth,
    investigationProgress,
    recommendations,
    lastSuccessfulRefreshAt: caseQuery.dataUpdatedAt > 0 ? new Date(caseQuery.dataUpdatedAt) : null,
    isRefreshing: caseQuery.isFetching || alertsQuery.isFetching || notesQuery.isFetching || auditQuery.isFetching,
    refresh: refreshAll,
  }
}
