import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { ShieldAlert } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { SkeletonRow } from '@/components/ui/Skeleton'
import { Pagination } from '@/components/ui/Pagination'
import { LiveIndicator } from '@/components/live/LiveIndicator'
import { RefreshButton } from '@/components/live/RefreshButton'
import { SecurityStateBar } from '@/features/dashboard/components/SecurityStateBar'
import { AlertsFilterToolbar } from '@/features/alerts/components/AlertsFilterToolbar'
import { AlertRow } from '@/features/alerts/components/AlertRow'
import { PrioritySortControl, type AlertSortMode } from '@/features/alerts/components/PrioritySortControl'
import { useAlertsListQuery } from '@/features/alerts/useAlertsListQuery'
import { compareAlertPriority } from '@/features/alerts/priority'
import { formatCount } from '@/lib/format'
import type { AlertsFilters } from '@/features/alerts/types'
import type { AlertStatus, DetectionSeverity } from '@/types/api'

export function AlertsPage() {
  const [searchParams, setSearchParams] = useSearchParams()

  const page = Math.max(1, Number(searchParams.get('page') ?? '1') || 1)
  const filters: AlertsFilters = useMemo(
    () => ({
      status: (searchParams.get('status') as AlertStatus) || undefined,
      severity: (searchParams.get('severity') as DetectionSeverity) || undefined,
      rule_id: searchParams.get('rule_id') || undefined,
      since: searchParams.get('since') || undefined,
      until: searchParams.get('until') || undefined,
    }),
    [searchParams],
  )

  const { alerts, hasNextPage, liveState, lastSuccessfulRefreshAt, isRefreshing, refresh } = useAlertsListQuery(page, filters)

  const sortMode: AlertSortMode = searchParams.get('sort') === 'priority' ? 'priority' : 'recent'
  const orderedAlerts = useMemo(
    () => (sortMode === 'priority' ? [...alerts].sort(compareAlertPriority) : alerts),
    [alerts, sortMode],
  )

  /** Step 12M Queue Summary: counts over ONLY the alerts this exact
   * GET /alerts page/filter combination returned -- never a database
   * COUNT(*), never a claim about the total SOC backlog. See the
   * disclaimer text rendered alongside this bar below. */
  const criticalOrHighCount = alerts.filter((a) => a.severity === 'critical' || a.severity === 'high').length
  const newCount = alerts.filter((a) => a.status === 'new').length
  const investigatingCount = alerts.filter((a) => a.status === 'investigating').length
  const escalatedCount = alerts.filter((a) => a.status === 'escalated').length

  function applyFilters(next: AlertsFilters) {
    const params = new URLSearchParams()
    if (next.status) params.set('status', next.status)
    if (next.severity) params.set('severity', next.severity)
    if (next.rule_id) params.set('rule_id', next.rule_id)
    if (next.since) params.set('since', next.since)
    if (next.until) params.set('until', next.until)
    if (sortMode === 'priority') params.set('sort', 'priority')
    setSearchParams(params)
  }

  function goToPage(nextPage: number) {
    const params = new URLSearchParams(searchParams)
    params.set('page', String(nextPage))
    setSearchParams(params)
  }

  function setSortMode(next: AlertSortMode) {
    const params = new URLSearchParams(searchParams)
    if (next === 'priority') params.set('sort', 'priority')
    else params.delete('sort')
    setSearchParams(params)
  }

  const hasFilters = Boolean(filters.status || filters.severity || filters.rule_id || filters.since || filters.until)

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <PageHeader
        title="Alert Queue"
        description="Operational alert triage workspace -- alerts returned by the current query, prioritized for analyst review"
        action={
          <div className="flex items-center gap-3">
            <PrioritySortControl mode={sortMode} onChange={setSortMode} />
            <LiveIndicator state={liveState} lastSuccessfulRefreshAt={lastSuccessfulRefreshAt} />
            <RefreshButton onRefresh={refresh} isRefreshing={isRefreshing} />
          </div>
        }
      />

      {liveState !== 'loading' && liveState !== 'error' && alerts.length > 0 && (
        <>
          {/* Step 12M Queue Summary -- counts only the alerts already
           * returned by this exact query/page, never a database
           * COUNT(*) and never presented as the total SOC backlog. */}
          <SecurityStateBar
            items={[
              { label: 'Alerts Returned', value: formatCount(alerts.length) },
              { label: 'Critical / High', value: formatCount(criticalOrHighCount), tone: criticalOrHighCount > 0 ? 'critical' : 'default' },
              { label: 'New', value: formatCount(newCount) },
              { label: 'Investigating', value: formatCount(investigatingCount) },
              { label: 'Escalated', value: formatCount(escalatedCount) },
            ]}
          />
          <p className="mt-1.5 text-[11px] text-fg-subtle">
            Summary of alerts returned in this view ({alerts.length} alert{alerts.length === 1 ? '' : 's'} on this page) — not a total SOC
            backlog.
          </p>
        </>
      )}

      <Card className="mt-4 overflow-hidden">
        <AlertsFilterToolbar filters={filters} onApply={applyFilters} onClear={() => setSearchParams({})} />

        {liveState === 'error' ? (
          <ErrorState title="Alert queue could not be loaded" onRetry={refresh} />
        ) : liveState === 'loading' ? (
          <div>
            {Array.from({ length: 6 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        ) : alerts.length === 0 ? (
          <EmptyState
            icon={ShieldAlert}
            title={hasFilters ? 'No alerts match the selected filters.' : 'No alerts were returned for this view.'}
            description={hasFilters ? 'Try clearing or widening the current filters.' : 'Waiting for telemetry, or no alerts exist yet.'}
          />
        ) : (
          <>
            {sortMode === 'priority' && (
              <p className="border-b border-border-faint px-5 py-2 text-[11px] text-fg-subtle">
                Priority order applies to this page only ({orderedAlerts.length} alert{orderedAlerts.length === 1 ? '' : 's'}) — it does not
                reorder alerts on other pages.
              </p>
            )}
            <ul className="list-none">
              {orderedAlerts.map((alert) => (
                <li key={alert.id}>
                  <AlertRow alert={alert} />
                </li>
              ))}
            </ul>
            <Pagination page={page} hasNext={hasNextPage} onPrevious={() => goToPage(page - 1)} onNext={() => goToPage(page + 1)} />
          </>
        )}
      </Card>
    </div>
  )
}
