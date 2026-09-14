import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Activity, Bot, FileSearch, Gauge, ShieldAlert, Stethoscope } from 'lucide-react'
import { CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { getHealth } from '@/services/healthService'
import { LIVE_REFRESH_INTERVAL_MS } from '@/lib/liveRefresh'
import { buildCaseContextQuery } from '@/features/cases/caseNavigationContext'
import type { CaseRead } from '@/types/api'

/** Right-rail widgets. Deliberately lean on network usage:
 *
 * - "Live System Health" is the ONE extra request this sidebar makes --
 *   GET /health is real, public, and already proven cheap/safe (see
 *   healthService.ts's own docstring on what it does and does not
 *   report). Polled on the same shared 15s interval every other live
 *   AMNIX surface uses, not a second timer mechanism.
 * - "Detection Health" is deliberately navigation-only, NOT a live
 *   embedded snapshot: Step 12O's own real data (deriveRuleObservability
 *   etc.) is built from GET /events + GET /alerts, both windowed and
 *   NOT in this Console's own declared allowed-request list (see
 *   useIncidentConsole.ts's docstring) -- embedding live numbers here
 *   would mean two more requests this page never otherwise makes. A
 *   nav card costs nothing and stays honest about what it is.
 * - "Telemetry Window selector" is intentionally OMITTED: there is no
 *   telemetry-windowed query anywhere on this page for a selector to
 *   control, so a decorative control with no real consumer was left out
 *   rather than added for its own sake (see the Step 12W completion
 *   report's own DEFERRED section).
 * - "Case Metadata" and "Quick Actions" use only data/routes that
 *   already exist on this page -- zero additional requests.
 */
export function CommandCenterSidebar({
  caseItem,
  focusedAlertId,
  focusedAlertRuleId,
  focusedAlertFirstEventId,
}: {
  caseItem: CaseRead
  focusedAlertId: string | undefined
  focusedAlertRuleId: string | undefined
  focusedAlertFirstEventId: string | undefined
}) {
  const healthQuery = useQuery({
    queryKey: ['console-system-health'],
    queryFn: getHealth,
    refetchInterval: LIVE_REFRESH_INTERVAL_MS,
    refetchIntervalInBackground: false,
  })

  const caseContextQuery = buildCaseContextQuery({ caseId: caseItem.id, caseNumber: caseItem.case_number })

  return (
    <aside className="flex flex-col gap-4">
      <div className="rounded-lg border border-border bg-surface">
        <CardHeader title="Live System Health" subtitle="GET /health" />
        <div className="px-5 pb-4">
          {healthQuery.isPending ? (
            <p className="text-xs text-fg-subtle">Checking…</p>
          ) : healthQuery.isError ? (
            <Badge tone="danger">Unreachable</Badge>
          ) : (
            <div className="flex items-center gap-2">
              <Activity className="size-3.5 text-success" strokeWidth={2} aria-hidden="true" />
              <Badge tone="success">{healthQuery.data?.status ?? 'unknown'}</Badge>
              <span className="text-[11px] text-fg-subtle">{healthQuery.data?.service}</span>
            </div>
          )}
        </div>
      </div>

      <Link to="/detection-health" className="block rounded-lg border border-border bg-surface transition-colors duration-fast hover:border-accent/30">
        <CardHeader title="Detection Health" subtitle="Rule & telemetry observability" action={<Stethoscope className="size-4 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />} />
        <p className="px-5 pb-4 text-xs text-fg-subtle">Open the Detection Health workspace →</p>
      </Link>

      <div className="rounded-lg border border-border bg-surface">
        <CardHeader title="Case Metadata" />
        <dl className="grid grid-cols-1 gap-2 px-5 pb-4 text-xs">
          <div className="flex justify-between gap-2">
            <dt className="text-fg-subtle">Case ID</dt>
            <dd className="truncate font-mono text-fg" title={caseItem.id}>
              {caseItem.id}
            </dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-fg-subtle">Created by</dt>
            <dd className="truncate font-mono text-fg" title={caseItem.created_by}>
              {caseItem.created_by}
            </dd>
          </div>
          {caseItem.closed_at && (
            <div className="flex justify-between gap-2">
              <dt className="text-fg-subtle">Closed</dt>
              <dd className="text-fg">{new Date(caseItem.closed_at).toLocaleDateString()}</dd>
            </div>
          )}
        </dl>
      </div>

      <div className="rounded-lg border border-border bg-surface">
        <CardHeader title="Quick Actions" />
        <div className="flex flex-col gap-1 px-3 pb-3">
          {focusedAlertId && (
            <>
              <Link to={`/alerts/${focusedAlertId}/investigation${caseContextQuery}`} className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-fg-muted hover:bg-surface-hover hover:text-fg">
                <FileSearch className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                Investigate Focused Alert
              </Link>
              {focusedAlertRuleId && (
                <Link to={`/rules/${focusedAlertRuleId}`} className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-fg-muted hover:bg-surface-hover hover:text-fg">
                  <ShieldAlert className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                  View Detection Rule
                </Link>
              )}
              <Link to={`/alerts/${focusedAlertId}/investigation${caseContextQuery}`} className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-fg-muted hover:bg-surface-hover hover:text-fg">
                <Bot className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                Open Copilot
              </Link>
              {focusedAlertFirstEventId && (
                <Link to={`/events/${focusedAlertFirstEventId}`} className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-fg-muted hover:bg-surface-hover hover:text-fg">
                  <Activity className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                  View Event
                </Link>
              )}
            </>
          )}
          <Link to="/alerts" className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-fg-muted hover:bg-surface-hover hover:text-fg">
            <ShieldAlert className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            Go to Alert Queue
          </Link>
          <Link to="/operations" className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-fg-muted hover:bg-surface-hover hover:text-fg">
            <Gauge className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            Go to Detection Operations
          </Link>
        </div>
      </div>
    </aside>
  )
}
