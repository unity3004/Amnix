import { useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { AlertTriangle, ShieldAlert } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { LiveIndicator } from '@/components/live/LiveIndicator'
import { RefreshButton } from '@/components/live/RefreshButton'
import { SecurityStateBar } from '@/features/dashboard/components/SecurityStateBar'
import { AlertRow } from '@/features/alerts/components/AlertRow'
import { AlertsFilterToolbar } from '@/features/alerts/components/AlertsFilterToolbar'
import { formatCount } from '@/lib/format'
import { OBSERVATION_WINDOW_OPTIONS } from '@/lib/observationWindow'
import { useDetectionOperations } from '@/features/operations/useDetectionOperations'
import {
  deriveSeverityDistribution,
  deriveStatusDistribution,
  deriveRuleActivity,
  deriveActivityTimeline,
} from '@/features/operations/deriveOperationsSummary'
import { AlertActivityChart } from '@/features/operations/components/AlertActivityChart'
import { compareAlertPriority } from '@/features/alerts/priority'
import type { AlertStatus, DetectionSeverity } from '@/types/api'
import type { AlertsFilters } from '@/features/alerts/types'

const STATUS_TONE: Record<AlertStatus, 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

const PRIORITY_QUEUE_LIMIT = 15

/** AMNIX Detection Operations (Step 12J).
 *
 * Exactly one real backend request per load/refresh/window-or-filter
 * change: GET /alerts (see useDetectionOperations). Every card/table/
 * chart below is either REAL OBSERVED DATA (the alerts themselves), a
 * STATIC DETECTION DEFINITION (the Step 12H rule registry, reused
 * unmodified), or a DERIVED ANALYST VIEW combining the two -- never a
 * fabricated score, percentage, trend, or historical total. Priority
 * ordering reuses the exact Step 12G comparator; nothing here invents
 * a second scoring algorithm.
 */
export function DetectionOperationsPage() {
  const [searchParams, setSearchParams] = useSearchParams()

  const windowMinutes = Number(searchParams.get('window') ?? '60') || 60
  const filters: Omit<AlertsFilters, 'since' | 'until'> = useMemo(
    () => ({
      status: (searchParams.get('status') as AlertStatus) || undefined,
      severity: (searchParams.get('severity') as DetectionSeverity) || undefined,
      rule_id: searchParams.get('rule_id') || undefined,
    }),
    [searchParams],
  )

  const { alerts, liveState, lastSuccessfulRefreshAt, isRefreshing, refresh } = useDetectionOperations(windowMinutes, filters)

  const severityCounts = useMemo(() => deriveSeverityDistribution(alerts), [alerts])
  const statusCounts = useMemo(() => deriveStatusDistribution(alerts), [alerts])
  const ruleActivity = useMemo(() => deriveRuleActivity(alerts), [alerts])
  const activityBuckets = useMemo(() => deriveActivityTimeline(alerts, windowMinutes), [alerts, windowMinutes])
  const priorityQueue = useMemo(() => [...alerts].sort(compareAlertPriority), [alerts])

  const windowLabel = OBSERVATION_WINDOW_OPTIONS.find((o) => o.minutes === windowMinutes)?.label ?? 'selected window'
  const criticalOrHighCount = severityCounts.filter((s) => s.severity === 'critical' || s.severity === 'high').reduce((a, s) => a + s.count, 0)
  const newCount = statusCounts.find((s) => s.status === 'new')?.count ?? 0
  const investigatingCount = statusCounts.find((s) => s.status === 'investigating')?.count ?? 0
  const hasActiveFilters = Boolean(filters.status || filters.severity || filters.rule_id)

  function setWindow(minutes: number) {
    const params = new URLSearchParams(searchParams)
    params.set('window', String(minutes))
    setSearchParams(params)
  }

  function applyFilters(next: AlertsFilters) {
    const params = new URLSearchParams()
    params.set('window', String(windowMinutes))
    if (next.status) params.set('status', next.status)
    if (next.severity) params.set('severity', next.severity)
    if (next.rule_id) params.set('rule_id', next.rule_id)
    setSearchParams(params)
  }

  function clearFilters() {
    const params = new URLSearchParams()
    params.set('window', String(windowMinutes))
    setSearchParams(params)
  }

  if (liveState === 'error') {
    return (
      <div className="mx-auto max-w-[1500px] px-6 py-6">
        <PageHeader title="Detection Operations" description="Monitor recent detection activity and prioritize alerts for investigation." />
        <Card>
          <ErrorState title="Unable to retrieve recent alerts" onRetry={refresh} />
        </Card>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <PageHeader title="Detection Operations" description="Monitor recent detection activity and prioritize alerts for investigation." />
        <div className="flex items-center gap-3">
          <label htmlFor="operations-window" className="text-xs text-fg-subtle">
            Observation window
          </label>
          <select
            id="operations-window"
            value={windowMinutes}
            onChange={(e) => setWindow(Number(e.target.value))}
            className="h-8 rounded-md border border-border bg-surface px-2 text-xs text-fg-muted transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none"
          >
            {OBSERVATION_WINDOW_OPTIONS.map((o) => (
              <option key={o.minutes} value={o.minutes}>
                {o.label}
              </option>
            ))}
          </select>
          <LiveIndicator state={liveState} lastSuccessfulRefreshAt={lastSuccessfulRefreshAt} />
          <RefreshButton onRefresh={refresh} isRefreshing={isRefreshing} />
        </div>
      </div>

      <Card className="mb-4 overflow-hidden">
        <AlertsFilterToolbar
          filters={filters}
          onApply={applyFilters}
          onClear={clearFilters}
          showTimeRange={false}
        />
      </Card>

      {liveState === 'loading' ? (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full" />
          ))}
        </div>
      ) : alerts.length === 0 ? (
        <Card>
          <EmptyState
            icon={ShieldAlert}
            title={hasActiveFilters ? 'No alerts match the current filters' : 'No recent alert activity in the selected window.'}
            description="Detection activity may simply be outside the selected observation window."
          />
        </Card>
      ) : (
        <>
          {/* ---- Section 1: Operational Summary ---- */}
          <SecurityStateBar
            items={[
              { label: 'Recent Alerts Returned', value: formatCount(alerts.length) },
              { label: 'Critical / High', value: formatCount(criticalOrHighCount), tone: criticalOrHighCount > 0 ? 'critical' : 'default' },
              { label: 'New', value: formatCount(newCount) },
              { label: 'Investigating', value: formatCount(investigatingCount) },
            ]}
          />
          <p className="mt-1.5 text-[11px] text-fg-subtle">
            {windowLabel} · bounded to the current API page ({alerts.length} alert{alerts.length === 1 ? '' : 's'} returned) — not a historical total.
          </p>

          {/* ---- Section 2: Alert Activity ---- */}
          <Card className="mt-4">
            <CardHeader title="Alert Activity" subtitle={`Activity observed in the ${windowLabel.toLowerCase()} (this bounded dataset only)`} />
            <div className="px-3 pb-4 pt-2">
              <AlertActivityChart buckets={activityBuckets} />
            </div>
          </Card>

          {/* ---- Section 3: Detection Activity by Rule ---- */}
          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Detection Activity by Rule" subtitle="Alerts returned in selected window, grouped by rule_id" />
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-[11px] uppercase tracking-wide text-fg-subtle">
                    <th className="px-5 py-2 font-medium">Rule</th>
                    <th className="px-3 py-2 font-medium">Severity</th>
                    <th className="px-5 py-2 font-medium">Recent Alert Count</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-faint">
                  {ruleActivity.map((entry) => (
                    <tr key={entry.ruleId}>
                      <td className="px-5 py-2.5">
                        {entry.ruleName ? (
                          <Link to={`/rules/${entry.ruleId}`} className="font-medium text-accent-strong hover:text-accent">
                            {entry.ruleName}
                          </Link>
                        ) : (
                          <span className="font-mono text-fg-muted" title="Unrecognized rule_id -- shown as-is, never a fabricated name">
                            {entry.ruleId}
                          </span>
                        )}
                        <p className="font-mono text-[10px] text-fg-subtle">{entry.ruleId}</p>
                      </td>
                      <td className="px-3 py-2.5">
                        <SeverityBadge severity={entry.observedSeverity} />
                      </td>
                      <td className="px-5 py-2.5 font-mono text-fg">{entry.recentAlertCount}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          {/* ---- Section 4: Severity Distribution ---- */}
          <Card className="mt-4">
            <CardHeader title="Severity Distribution" subtitle="Real severities of alerts returned in this view" />
            <div className="grid grid-cols-2 gap-3 px-5 pb-5 sm:grid-cols-4">
              {severityCounts.map(({ severity, count }) => (
                <div key={severity} className="flex flex-col items-start gap-1 rounded-md border border-border-faint bg-bg-inset px-3 py-2.5">
                  <SeverityBadge severity={severity} />
                  {count > 0 ? (
                    <span className="text-lg font-semibold tabular-nums text-fg">{count}</span>
                  ) : (
                    <span className="text-xs text-fg-subtle">No {severity} alerts returned in this view.</span>
                  )}
                </div>
              ))}
            </div>
          </Card>

          {/* ---- Section 5: Status / Queue Health ---- */}
          <Card className="mt-4">
            <CardHeader title="Current Alert Status Distribution" subtitle="Alerts returned by status in this view" />
            <div className="grid grid-cols-2 gap-3 px-5 pb-5 sm:grid-cols-5">
              {statusCounts.map(({ status, count }) => (
                <div key={status} className="flex flex-col items-start gap-1 rounded-md border border-border-faint bg-bg-inset px-3 py-2.5">
                  <Badge tone={STATUS_TONE[status]}>{status}</Badge>
                  <span className="text-lg font-semibold tabular-nums text-fg">{count}</span>
                </div>
              ))}
            </div>
          </Card>

          {/* ---- Section 6: Priority Queue ---- */}
          <Card className="mt-4 overflow-hidden">
            <CardHeader
              title="Priority Queue"
              subtitle={`Top ${Math.min(PRIORITY_QUEUE_LIMIT, priorityQueue.length)} of ${priorityQueue.length} alert(s) in this bounded view, ordered by severity · status · recency (Step 12G)`}
            />
            <div>
              {priorityQueue.slice(0, PRIORITY_QUEUE_LIMIT).map((alert) => (
                <AlertRow key={alert.id} alert={alert} />
              ))}
            </div>
          </Card>
        </>
      )}

      {liveState === 'degraded' && (
        <div className="mt-3 flex items-center gap-2 text-xs text-warning">
          <AlertTriangle className="size-3.5 shrink-0" strokeWidth={1.75} aria-hidden="true" />
          Showing the last successfully retrieved data -- the most recent refresh attempt failed.
        </div>
      )}
    </div>
  )
}
