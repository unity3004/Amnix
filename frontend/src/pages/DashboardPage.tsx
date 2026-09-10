import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertOctagon, Activity, FolderSearch, ShieldAlert } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { SkeletonCard, SkeletonRow, Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { useAuth } from '@/features/auth/useAuth'
import { useDashboardOverview } from '@/features/dashboard/useDashboardOverview'
import { MetricCard } from '@/features/dashboard/components/MetricCard'
import { ThreatActivityChart } from '@/features/dashboard/components/ThreatActivityChart'
import { RecentAlertsPanel } from '@/features/dashboard/components/RecentAlertsPanel'
import { SeverityDistribution } from '@/features/dashboard/components/SeverityDistribution'
import { MitreActivityPanel } from '@/features/dashboard/components/MitreActivityPanel'
import { SystemStatusPanel } from '@/features/dashboard/components/SystemStatusPanel'
import { formatClockTime } from '@/lib/format'

function greeting(date: Date): string {
  const hour = date.getHours()
  if (hour < 12) return 'Good morning'
  if (hour < 18) return 'Good afternoon'
  return 'Good evening'
}

export function DashboardPage() {
  const { user } = useAuth()
  const { data, isLoading, isError, refetch } = useDashboardOverview()
  const navigate = useNavigate()
  const now = useMemo(() => new Date(), [])
  const analystName = user?.email.split('@')[0] ?? 'Analyst'

  return (
    <div className="mx-auto max-w-[1400px] px-6 py-6">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-fg">
            {greeting(now)}, <span className="capitalize">{analystName}</span>
          </h1>
          <p className="mt-1 text-sm text-fg-subtle">Security Operations Overview</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-fg-subtle">
          <span className="flex items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 py-1.5">
            <span className="size-1.5 rounded-full bg-success" aria-hidden="true" />
            Monitoring active
          </span>
          <span>Last updated {formatClockTime(now)}</span>
        </div>
      </div>

      {isError && (
        <Card className="mb-6">
          <ErrorState onRetry={() => refetch()} />
        </Card>
      )}

      {!isError && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {isLoading || !data ? (
              Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />)
            ) : (
              <>
                <MetricCard label="Total Alerts" value={data.metrics.totalAlerts} icon={ShieldAlert} tone="accent" supporting="Last 30 days" />
                <MetricCard
                  label="Critical Alerts"
                  value={data.metrics.criticalAlerts}
                  icon={AlertOctagon}
                  tone="critical"
                  supporting="Requires attention"
                />
                <MetricCard
                  label="Open Investigations"
                  value={data.metrics.openInvestigations}
                  icon={FolderSearch}
                  supporting="In progress"
                />
                <MetricCard label="Events Today" value={data.metrics.eventsToday} icon={Activity} supporting="Ingested telemetry" />
              </>
            )}
          </div>

          <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
            <div className="flex flex-col gap-4 xl:col-span-2">
              <Card>
                <CardHeader title="Threat Activity" subtitle="Alerts by severity, last 24 hours" />
                <div className="px-3 pb-4">
                  {isLoading || !data ? <Skeleton className="h-64 w-full" /> : <ThreatActivityChart data={data.activity} />}
                </div>
              </Card>

              <Card className="overflow-hidden">
                <CardHeader title="Recent Alerts" subtitle="Most recent detections across your environment" />
                {isLoading || !data ? (
                  <div className="divide-y divide-border-faint">
                    {Array.from({ length: 4 }).map((_, i) => (
                      <SkeletonRow key={i} />
                    ))}
                  </div>
                ) : (
                  <RecentAlertsPanel alerts={data.recentAlerts} onSelect={(id) => navigate(`/alerts?focus=${id}`)} />
                )}
              </Card>
            </div>

            <div className="flex flex-col gap-4">
              <Card>
                <CardHeader title="Severity Distribution" subtitle="Open + recent alerts" />
                <div className="px-5 pb-5">
                  {isLoading || !data ? (
                    <div className="flex flex-col gap-3">
                      {Array.from({ length: 4 }).map((_, i) => (
                        <Skeleton key={i} className="h-4 w-full" />
                      ))}
                    </div>
                  ) : (
                    <SeverityDistribution data={data.severityDistribution} />
                  )}
                </div>
              </Card>

              <Card className="overflow-hidden">
                <CardHeader title="MITRE ATT&CK Activity" subtitle="Techniques observed via detections" />
                {isLoading || !data ? (
                  <div className="divide-y divide-border-faint">
                    {Array.from({ length: 3 }).map((_, i) => (
                      <SkeletonRow key={i} />
                    ))}
                  </div>
                ) : (
                  <MitreActivityPanel entries={data.mitreActivity} />
                )}
              </Card>

              <Card>
                <CardHeader title="System Status" />
                <SystemStatusPanel />
              </Card>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
