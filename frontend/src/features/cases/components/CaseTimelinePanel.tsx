import { useState } from 'react'
import { IncidentTimelinePanel } from '@/features/console/components/IncidentTimelinePanel'
import { buildIncidentTimeline } from '@/features/console/logic'
import { useInvestigation } from '@/features/investigation/useInvestigation'
import { useAlertCopilotAudits } from '@/features/console/useAlertCopilotAudits'
import type { AlertRead, CaseAuditResponse, CaseNoteResponse, CaseRead } from '@/types/api'

/** Step 13B: the Case Investigation Timeline for CaseDetailPage.
 *
 * Reuses the Step 12W Incident Console's own proven merge/render
 * pipeline VERBATIM -- buildIncidentTimeline() (features/console/logic.ts)
 * and IncidentTimelinePanel (features/console/components) -- rather than
 * building a second timeline implementation, per this step's own
 * explicit instruction. This component is only the thin, Case-Detail-
 * specific wiring around that shared pipeline: which data to feed it,
 * and how the analyst picks which linked alert's telemetry/Copilot
 * activity to include.
 *
 * CASE audit + CASE notes are supplied by the caller (already loaded by
 * CaseDetailPage for its own Audit/Notes panels -- zero extra request).
 * SecurityEvent/Copilot data is intentionally scoped to ONE
 * analyst-selected "focused" alert at a time, exactly like the Console:
 * GET /alerts/{id}/investigation and GET /alerts/{id}/copilot/audits are
 * both alert-scoped with no bulk variant, so looping either across every
 * linked alert would be the N+1 pattern this codebase has repeatedly
 * ruled out. Unlike the Console (an explicit "investigate this incident"
 * workspace, which auto-focuses the top-priority alert on load), this
 * lighter Case Detail view starts with NO alert focused -- the analyst
 * must explicitly choose one before any investigation/Copilot request
 * fires. This also means the same underlying SecurityEvent can never be
 * shown twice from two different alerts simultaneously (Step 13B §11's
 * stated duplicate-handling risk): only one alert's events are ever
 * loaded into the timeline at once.
 */
export function CaseTimelinePanel({
  caseItem,
  alerts,
  notes,
  audits,
}: {
  caseItem: CaseRead
  alerts: AlertRead[]
  notes: CaseNoteResponse[]
  audits: CaseAuditResponse[]
}) {
  const [focusedAlertId, setFocusedAlertId] = useState<string | undefined>(undefined)

  const investigationQuery = useInvestigation(focusedAlertId)
  const copilotAuditsQuery = useAlertCopilotAudits(focusedAlertId)

  const timeline = buildIncidentTimeline({
    audits,
    notes,
    focusedAlertTimeline: investigationQuery.data?.timeline,
    focusedAlertCopilotAudits: copilotAuditsQuery.data?.items,
  })

  const alertSelector =
    alerts.length > 0 ? (
      <div className="border-b border-border px-5 py-3">
        <label htmlFor="case-timeline-alert-select" className="text-[11px] uppercase tracking-wide text-fg-subtle">
          Include telemetry from alert
        </label>
        <select
          id="case-timeline-alert-select"
          value={focusedAlertId ?? ''}
          onChange={(e) => setFocusedAlertId(e.target.value || undefined)}
          className="mt-1.5 h-9 w-full rounded-md border border-border bg-surface px-2 text-sm text-fg focus:border-accent/50 focus:outline-none sm:w-auto"
        >
          <option value="">— none selected —</option>
          {alerts.map((a) => (
            <option key={a.id} value={a.id}>
              {a.title} ({a.severity})
            </option>
          ))}
        </select>
        {investigationQuery.isPending && focusedAlertId && (
          <p className="mt-1.5 text-xs text-fg-subtle">Loading this alert's investigation…</p>
        )}
        {investigationQuery.isError && <p className="mt-1.5 text-xs text-fg-subtle">This alert's investigation could not be loaded.</p>}
      </div>
    ) : undefined

  return (
    <IncidentTimelinePanel
      entries={timeline}
      focusedAlertLoaded={Boolean(investigationQuery.data)}
      caseId={caseItem.id}
      caseNumber={caseItem.case_number}
      alertSelector={alertSelector}
    />
  )
}
