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
import { AlertsFilterToolbar } from '@/features/alerts/components/AlertsFilterToolbar'
import { AlertRow } from '@/features/alerts/components/AlertRow'
import { PrioritySortControl, type AlertSortMode } from '@/features/alerts/components/PrioritySortControl'
import { useAlertsListQuery } from '@/features/alerts/useAlertsListQuery'
import { compareAlertPriority } from '@/features/alerts/priority'
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
        title="Alerts"
        description="Security detections requiring analyst attention"
        action={
          <div className="flex items-center gap-3">
            <PrioritySortControl mode={sortMode} onChange={setSortMode} />
            <LiveIndicator state={liveState} lastSuccessfulRefreshAt={lastSuccessfulRefreshAt} />
            <RefreshButton onRefresh={refresh} isRefreshing={isRefreshing} />
          </div>
        }
      />

      <Card className="overflow-hidden">
        <AlertsFilterToolbar filters={filters} onApply={applyFilters} onClear={() => setSearchParams({})} />

        {liveState === 'error' ? (
          <ErrorState title="Unable to retrieve alerts" onRetry={refresh} />
        ) : liveState === 'loading' ? (
          <div>
            {Array.from({ length: 6 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        ) : alerts.length === 0 ? (
          <EmptyState
            icon={ShieldAlert}
            title={hasFilters ? 'No alerts match' : 'No security events'}
            description={hasFilters ? 'No alerts match the current filters.' : 'Waiting for telemetry.'}
          />
        ) : (
          <>
            {sortMode === 'priority' && (
              <p className="border-b border-border-faint px-5 py-2 text-[11px] text-fg-subtle">
                Priority order applies to this page only ({orderedAlerts.length} alert{orderedAlerts.length === 1 ? '' : 's'}) — it does not
                reorder alerts on other pages.
              </p>
            )}
            <div>
              {orderedAlerts.map((alert) => (
                <AlertRow key={alert.id} alert={alert} />
              ))}
            </div>
            <Pagination page={page} hasNext={hasNextPage} onPrevious={() => goToPage(page - 1)} onNext={() => goToPage(page + 1)} />
          </>
        )}
      </Card>
    </div>
  )
}
