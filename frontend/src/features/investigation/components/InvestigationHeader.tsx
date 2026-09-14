import { useNavigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { SeverityBadge, Badge } from '@/components/ui/Badge'
import { WorkflowBreadcrumb, type BreadcrumbStep } from '@/components/layout/WorkflowBreadcrumb'
import { buildCaseContextQuery, type CaseNavigationContext } from '@/features/cases/caseNavigationContext'
import type { AlertRead } from '@/types/api'

const STATUS_TONE: Record<AlertRead['status'], 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

/** REAL BACKEND DATA -- every field below is GET /alerts/{id} verbatim.
 * Section A of the investigation workspace.
 */
export function InvestigationHeader({
  alert,
  caseContext,
}: {
  alert: AlertRead
  /** Step 12U: present only when the analyst arrived via Case ->
   * Alert -> Investigate (see caseNavigationContext.ts). Purely
   * navigational -- never implies Investigation itself is Case-scoped
   * or persisted anywhere against the Case. */
  caseContext: CaseNavigationContext | null
}) {
  const navigate = useNavigate()
  const alertHref = `/alerts/${alert.id}${caseContext ? buildCaseContextQuery(caseContext) : ''}`
  // Step 12Z §12: same real-levels-only rule as AlertDetailPage's own
  // breadcrumb -- "Case #N" only when Step 12U's context says that's
  // genuinely where the analyst came from.
  const breadcrumbSteps: BreadcrumbStep[] = caseContext
    ? [
        { label: 'SOC Cases', to: '/cases' },
        { label: 'Case', to: `/cases/${caseContext.caseId}` },
        { label: 'Alert', to: alertHref },
        { label: 'Investigation' },
      ]
    : [
        { label: 'Alerts', to: '/alerts' },
        { label: 'Alert', to: alertHref },
        { label: 'Investigation' },
      ]

  return (
    <div className="border-b border-border pb-4">
      <button
        type="button"
        onClick={() => navigate(caseContext ? `/cases/${caseContext.caseId}` : '/alerts')}
        className="mb-3 flex items-center gap-1.5 text-xs text-fg-subtle transition-colors duration-fast hover:text-fg"
      >
        <ArrowLeft className="size-3.5" strokeWidth={2} aria-hidden="true" />
        {caseContext ? `Back to Case #${caseContext.caseNumber}` : 'Back to Alerts'}
      </button>

      <WorkflowBreadcrumb steps={breadcrumbSteps} />

      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <Badge tone={STATUS_TONE[alert.status]}>{alert.status}</Badge>
          </div>
          <h1 className="mt-2 text-lg font-semibold text-fg">{alert.title}</h1>
          <p className="mt-1 font-mono text-xs text-fg-subtle">{alert.rule_id}</p>
        </div>
        <p className="shrink-0 font-mono text-[11px] text-fg-subtle" title="Alert ID">
          {alert.id}
        </p>
      </div>

      <dl className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div>
          <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Detection Time</dt>
          <dd className="mt-0.5 text-sm text-fg">{new Date(alert.first_seen).toLocaleString()}</dd>
        </div>
        <div>
          <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">First Seen</dt>
          <dd className="mt-0.5 text-sm text-fg">{new Date(alert.first_seen).toLocaleString()}</dd>
        </div>
        <div>
          <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Last Seen</dt>
          <dd className="mt-0.5 text-sm text-fg">{new Date(alert.last_seen).toLocaleString()}</dd>
        </div>
        <div>
          <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Related Events</dt>
          <dd className="mt-0.5 text-sm text-fg">{alert.source_event_ids.length}</dd>
        </div>
      </dl>
    </div>
  )
}
