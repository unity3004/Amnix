import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, CardHeader } from '@/components/ui/Card'
import { Skeleton, SkeletonRow } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { useDashboardData } from '@/features/dashboard/useDashboardData'
import { LiveIndicator } from '@/components/live/LiveIndicator'
import { RefreshButton } from '@/components/live/RefreshButton'
import { SecurityStateBar } from '@/features/dashboard/components/SecurityStateBar'
import { ThreatActivityChart } from '@/features/dashboard/components/ThreatActivityChart'
import { ThreatPulsePanel } from '@/features/dashboard/components/ThreatPulsePanel'
import { ActiveThreatsPanel } from '@/features/dashboard/components/ActiveThreatsPanel'
import { LiveEventStreamPanel } from '@/features/dashboard/components/LiveEventStreamPanel'
import { InvestigationActivityPanel } from '@/features/dashboard/components/InvestigationActivityPanel'
import { MitreActivityPanel } from '@/features/dashboard/components/MitreActivityPanel'
import { CopilotPanel } from '@/features/dashboard/components/CopilotPanel'
import { SystemStatusPanel } from '@/features/dashboard/components/SystemStatusPanel'
import { deriveActiveThreats } from '@/features/dashboard/derive/deriveActiveThreats'
import { deriveEventStream } from '@/features/dashboard/derive/deriveEventStream'
import { deriveInvestigationActivity } from '@/features/dashboard/derive/deriveInvestigationActivity'
import { deriveMitreActivity } from '@/features/dashboard/derive/deriveMitreActivity'
import { deriveThreatActivity } from '@/features/dashboard/derive/deriveThreatActivity'
import { deriveThreatPulse } from '@/features/dashboard/derive/deriveThreatPulse'
import { formatCount } from '@/lib/format'

export function DashboardPage() {
  const navigate = useNavigate()
  const {
    alerts,
    alertsError,
    alertsLoading,
    events,
    eventsError,
    eventsLoading,
    health,
    healthError,
    liveState,
    lastSuccessfulRefreshAt,
    isRefreshing,
    refreshAll,
  } = useDashboardData()

  // All REAL-DATA derivations below operate on the exact same bounded
  // alerts/events arrays useDashboardData() fetched this cycle -- no
  // component re-fetches anything itself (brief §4/§28: one events
  // request, one alerts request per refresh cycle).
  const activeThreats = useMemo(() => deriveActiveThreats(alerts), [alerts])
  const eventStream = useMemo(() => deriveEventStream(events), [events])
  const threatActivity = useMemo(() => deriveThreatActivity(alerts), [alerts])
  const threatPulse = useMemo(() => deriveThreatPulse(alerts), [alerts])
  const mitreActivity = useMemo(() => deriveMitreActivity(alerts), [alerts])
  const investigationActivity = useMemo(() => deriveInvestigationActivity(alerts), [alerts])

  const criticalCount = alerts.filter((a) => a.severity === 'critical').length

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      {/* ---- Header ---- */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-fg">Security Operations</h1>
          <p className="mt-0.5 text-sm text-fg-subtle">Live monitoring across your environment</p>
        </div>
        <div className="flex items-center gap-3">
          <LiveIndicator state={liveState} lastSuccessfulRefreshAt={lastSuccessfulRefreshAt} />
          <RefreshButton onRefresh={refreshAll} isRefreshing={isRefreshing} />
        </div>
      </div>

      {/* ---- Security instrumentation strip (REAL, scoped counts) ---- */}
      <SecurityStateBar
        items={[
          { label: 'Active Alerts (recent)', value: formatCount(alerts.length), tone: criticalCount > 0 ? 'critical' : 'default' },
          { label: 'Events (recent)', value: formatCount(events.length) },
          {
            label: 'Investigating',
            value: formatCount(investigationActivity.find((g) => g.stage === 'investigating')?.alerts.length ?? 0),
          },
          { label: 'Copilot', value: 'READY', tone: 'success' },
        ]}
      />

      {/* ---- Hero: Live Threat Activity ---- */}
      <Card className="mt-4">
        <div className="flex flex-wrap items-center justify-between gap-2 px-5 pt-4">
          <div>
            <h2 className="text-sm font-semibold tracking-wide text-fg">Live Threat Activity</h2>
            <p className="mt-0.5 text-xs text-fg-subtle">Security activity detected across monitored telemetry, last 24 hours</p>
          </div>
          <ThreatPulsePanel state={threatPulse} />
        </div>
        <div className="px-3 pb-4 pt-2">
          {alertsLoading && alerts.length === 0 ? (
            <Skeleton className="h-64 w-full" />
          ) : alertsError && alerts.length === 0 ? (
            <ErrorState title="Unable to load threat activity" onRetry={refreshAll} />
          ) : (
            <ThreatActivityChart data={threatActivity} />
          )}
        </div>
      </Card>

      {/* ---- Active Threats + Live Event Stream ---- */}
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card className="overflow-hidden">
          <CardHeader title="Active Threats" subtitle="Most recent detections across your environment" />
          {alertsLoading && alerts.length === 0 ? (
            <div className="divide-y divide-border-faint">
              {Array.from({ length: 4 }).map((_, i) => (
                <SkeletonRow key={i} />
              ))}
            </div>
          ) : alertsError && alerts.length === 0 ? (
            <ErrorState title="Unable to retrieve alerts" onRetry={refreshAll} />
          ) : (
            <ActiveThreatsPanel threats={activeThreats} onSelect={(id) => navigate(`/alerts/${id}`)} />
          )}
        </Card>

        <Card className="overflow-hidden">
          <CardHeader title="Live Event Stream" subtitle="Newest ingested telemetry" />
          {eventsLoading && events.length === 0 ? (
            <div className="divide-y divide-border-faint">
              {Array.from({ length: 5 }).map((_, i) => (
                <SkeletonRow key={i} />
              ))}
            </div>
          ) : eventsError && events.length === 0 ? (
            <ErrorState title="Unable to retrieve telemetry" onRetry={refreshAll} />
          ) : (
            <div className="max-h-96 overflow-y-auto">
              <LiveEventStreamPanel events={eventStream} onSelect={(id) => navigate(`/events/${id}`)} />
            </div>
          )}
        </Card>
      </div>

      {/* ---- Investigation Activity + MITRE Activity ---- */}
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card className="overflow-hidden">
          <CardHeader title="Investigation Activity" subtitle="Alert lifecycle across the recent queue" />
          {alertsLoading && alerts.length === 0 ? (
            <Skeleton className="mx-5 mb-4 h-20 w-auto" />
          ) : (
            <InvestigationActivityPanel groups={investigationActivity} />
          )}
        </Card>

        <Card className="overflow-hidden">
          <CardHeader title="MITRE ATT&CK Activity" subtitle="Techniques observed, based on recent alerts" />
          {alertsLoading && alerts.length === 0 ? (
            <div className="divide-y divide-border-faint">
              {Array.from({ length: 3 }).map((_, i) => (
                <SkeletonRow key={i} />
              ))}
            </div>
          ) : mitreActivity.length === 0 ? (
            <p className="px-5 pb-5 text-xs text-fg-subtle">No MITRE-mapped techniques observed in the current alert queue.</p>
          ) : (
            <MitreActivityPanel entries={mitreActivity} />
          )}
        </Card>
      </div>

      {/* ---- AI Copilot + System Health ---- */}
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CopilotPanel selectedAlertId={activeThreats[0]?.id ?? null} />
        </Card>

        <Card>
          <CardHeader title="System Health" />
          <SystemStatusPanel health={health} isLoading={!health && !healthError} isError={healthError} />
        </Card>
      </div>
    </div>
  )
}
