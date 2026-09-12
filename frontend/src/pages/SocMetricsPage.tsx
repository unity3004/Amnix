import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ShieldAlert } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { LiveIndicator } from '@/components/live/LiveIndicator'
import { RefreshButton } from '@/components/live/RefreshButton'
import { SecurityStateBar } from '@/features/dashboard/components/SecurityStateBar'
import { AlertActivityChart } from '@/features/operations/components/AlertActivityChart'
import {
  deriveSeverityDistribution,
  deriveStatusDistribution,
  deriveRuleActivity,
  deriveActivityTimeline,
} from '@/features/operations/deriveOperationsSummary'
import { deriveEvidenceAvailability, latestEventTimestamp } from '@/features/metrics/deriveMetricsInsights'
import { deriveEventTypeInventory, deriveSourceInventory } from '@/features/telemetry/deriveTelemetryInventory'
import { useTelemetryHealth, TELEMETRY_WINDOW_OPTIONS } from '@/features/telemetry/useTelemetryHealth'
import { getMitreTechniquesForRule } from '@/features/dashboard/mitreRegistry'
import { formatCount, formatRelativeTime } from '@/lib/format'
import type { AlertStatus } from '@/types/api'

const STATUS_TONE: Record<AlertStatus, 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

const STATUS_LABEL: Record<AlertStatus, string> = {
  new: 'New',
  acknowledged: 'Acknowledged',
  investigating: 'Investigating',
  resolved: 'Resolved',
  escalated: 'Escalated',
}

/** AMNIX SOC Metrics (Step 12N).
 *
 * Exactly two real backend requests per load/refresh/window-change --
 * GET /alerts and GET /events, both already existing (Step 12B), both
 * bounded by the analyst-selected observation window's `since` filter,
 * reusing useTelemetryHealth() (Step 12I) unmodified rather than adding
 * a third data-fetching hook. Every card/chart/table below is either
 * REAL OBSERVED DATA, a STATIC DETECTION DEFINITION (the Step 12H rule
 * registry / Step 12E MITRE registry, reused unmodified), or a
 * DERIVED ANALYST VIEW combining the two (Step 12J's own derive
 * functions, reused unmodified, plus one new file for the two metrics
 * genuinely new to this step: evidence availability and latest-event
 * timestamp) -- never a fabricated score, percentage, MTTR/MTTD,
 * analyst-performance figure, or historical total.
 *
 * Discovery finding (see the Step 12N report's Unsupported Metrics
 * section): AMNIX has no audit trail of alert status transitions, no
 * analyst/ownership field, and no bulk Copilot-usage aggregate API.
 * MTTR, MTTD, analyst productivity, SLA compliance, historical trend
 * comparisons, investigation-completion counts, and Copilot-usage
 * counts are therefore not shown anywhere on this page -- not because
 * they were forgotten, but because the current API cannot prove them.
 */
export function SocMetricsPage() {
  const [windowMinutes, setWindowMinutes] = useState(TELEMETRY_WINDOW_OPTIONS[1].minutes)
  const { events, eventsLiveState, alerts, alertsLiveState, lastSuccessfulRefreshAt, isRefreshing, refresh } =
    useTelemetryHealth(windowMinutes)

  const severityCounts = useMemo(() => deriveSeverityDistribution(alerts), [alerts])
  const statusCounts = useMemo(() => deriveStatusDistribution(alerts), [alerts])
  const ruleActivity = useMemo(() => deriveRuleActivity(alerts), [alerts])
  const activityBuckets = useMemo(() => deriveActivityTimeline(alerts, windowMinutes), [alerts, windowMinutes])
  const evidenceAvailability = useMemo(() => deriveEvidenceAvailability(alerts), [alerts])
  const eventTypeInventory = useMemo(() => deriveEventTypeInventory(events), [events])
  const sourceInventory = useMemo(() => deriveSourceInventory(events), [events])
  const latestEvent = useMemo(() => latestEventTimestamp(events), [events])

  const windowLabel = TELEMETRY_WINDOW_OPTIONS.find((o) => o.minutes === windowMinutes)?.label ?? 'selected window'
  const criticalOrHighCount = severityCounts.filter((s) => s.severity === 'critical' || s.severity === 'high').reduce((a, s) => a + s.count, 0)
  const newCount = statusCounts.find((s) => s.status === 'new')?.count ?? 0
  const investigatingCount = statusCounts.find((s) => s.status === 'investigating')?.count ?? 0
  const escalatedCount = statusCounts.find((s) => s.status === 'escalated')?.count ?? 0

  const alertsFailed = alertsLiveState === 'error'
  const eventsFailed = eventsLiveState === 'error'

  if (alertsFailed && eventsFailed) {
    return (
      <div className="mx-auto max-w-[1500px] px-6 py-6">
        <PageHeader title="SOC Metrics" description="Operational insights from the currently available AMNIX telemetry." />
        <Card>
          <ErrorState title="SOC metrics could not be loaded" onRetry={refresh} />
        </Card>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <PageHeader title="SOC Metrics" description="Operational insights from the currently available AMNIX telemetry." />
        <div className="flex items-center gap-3">
          <label htmlFor="metrics-window" className="text-xs text-fg-subtle">
            Observation window
          </label>
          <select
            id="metrics-window"
            value={windowMinutes}
            onChange={(e) => setWindowMinutes(Number(e.target.value))}
            className="h-8 rounded-md border border-border bg-surface px-2 text-xs text-fg-muted transition-colors duration-fast hover:border-border-strong focus:border-accent/50 focus:outline-none"
          >
            {TELEMETRY_WINDOW_OPTIONS.map((o) => (
              <option key={o.minutes} value={o.minutes}>
                {o.label}
              </option>
            ))}
          </select>
          <LiveIndicator state={alertsLiveState} lastSuccessfulRefreshAt={lastSuccessfulRefreshAt} />
          <RefreshButton onRefresh={refresh} isRefreshing={isRefreshing} />
        </div>
      </div>

      {alertsFailed ? (
        <Card>
          <ErrorState title="SOC metrics could not be loaded" onRetry={refresh} />
        </Card>
      ) : alertsLiveState === 'loading' ? (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full" />
          ))}
        </div>
      ) : alerts.length === 0 ? (
        <Card>
          <EmptyState
            icon={ShieldAlert}
            title="No alert activity is available for the selected view."
            description="Metrics reflect the alerts returned by the current query -- try widening the observation window."
          />
        </Card>
      ) : (
        <>
          {/* ---- Section 1: Top Summary ---- */}
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
            Metrics reflect the alerts returned by the current query, bounded to the {windowLabel.toLowerCase()} ({alerts.length}{' '}
            alert{alerts.length === 1 ? '' : 's'} returned) — not a total SOC backlog.
          </p>

          {/* ---- Section 2: Alert Activity ---- */}
          <Card className="mt-4">
            <CardHeader title="Alert Activity" subtitle={`Alert activity observed in the ${windowLabel.toLowerCase()} (this bounded dataset only)`} />
            <div className="px-3 pb-4 pt-2">
              <AlertActivityChart buckets={activityBuckets} />
            </div>
          </Card>

          {/* ---- Section 3: Current Alert Status Distribution ---- */}
          <Card className="mt-4">
            <CardHeader title="Current Alert Status Distribution" subtitle="Alerts returned by status in this view" />
            <div className="grid grid-cols-2 gap-3 px-5 pb-5 sm:grid-cols-5">
              {statusCounts.map(({ status, count }) => (
                <div key={status} className="flex flex-col items-start gap-1 rounded-md border border-border-faint bg-bg-inset px-3 py-2.5">
                  <Badge tone={STATUS_TONE[status]}>{status}</Badge>
                  {count > 0 ? (
                    <span className="text-lg font-semibold tabular-nums text-fg">{count}</span>
                  ) : (
                    <span className="text-xs text-fg-subtle">No {STATUS_LABEL[status].toLowerCase()} alerts returned in this view.</span>
                  )}
                </div>
              ))}
            </div>
          </Card>

          {/* ---- Section 4: Severity Distribution ---- */}
          <Card className="mt-4">
            <CardHeader title="Severity Distribution" subtitle="Real severities of alerts returned in this view" />
            <div className="grid grid-cols-2 gap-3 px-5 pb-5 sm:grid-cols-4">
              {severityCounts.map(({ severity, count }) => (
                <div key={severity} className="flex flex-col items-start gap-1 rounded-md border border-border-faint bg-bg-inset px-3 py-2.5">
                  <Badge tone={severity}>{severity}</Badge>
                  {count > 0 ? (
                    <span className="text-lg font-semibold tabular-nums text-fg">{count}</span>
                  ) : (
                    <span className="text-xs text-fg-subtle">No {severity} alerts returned in this view.</span>
                  )}
                </div>
              ))}
            </div>
          </Card>

          {/* ---- Section 5: Alert Activity by Detection Rule ---- */}
          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Alert Activity by Detection Rule" subtitle="Alerts returned in the selected window, grouped by rule_id -- never a claim about which rule is most effective" />
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-[11px] uppercase tracking-wide text-fg-subtle">
                    <th className="px-5 py-2 font-medium">Rule</th>
                    <th className="px-3 py-2 font-medium">Severity</th>
                    <th className="px-3 py-2 font-medium">MITRE</th>
                    <th className="px-5 py-2 font-medium">Alert Count</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-faint">
                  {ruleActivity.map((entry) => {
                    const techniques = getMitreTechniquesForRule(entry.ruleId)
                    return (
                      <tr key={entry.ruleId}>
                        <td className="px-5 py-2.5">
                          {entry.ruleName ? (
                            <span className="font-medium text-fg">{entry.ruleName}</span>
                          ) : (
                            <span className="font-mono text-fg-muted" title="Unrecognized rule_id -- shown as-is, never a fabricated name">
                              {entry.ruleId}
                            </span>
                          )}
                          <p className="font-mono text-[10px] text-fg-subtle">{entry.ruleId}</p>
                        </td>
                        <td className="px-3 py-2.5">
                          <Badge tone={entry.observedSeverity}>{entry.observedSeverity}</Badge>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-fg-subtle">
                          {techniques.length > 0 ? techniques.map((t) => t.techniqueId).join(', ') : 'No mapping'}
                        </td>
                        <td className="px-5 py-2.5 font-mono text-fg">{entry.recentAlertCount}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </Card>

          {/* ---- Section 6: Evidence Availability -- presence only,
           * never a quality/confidence/success claim. ---- */}
          <Card className="mt-4">
            <CardHeader
              title="Evidence Availability"
              subtitle="Whether triage data was recorded for alerts in this view -- not a measure of detection quality or threat confidence"
            />
            <div className="grid grid-cols-1 gap-3 px-5 pb-5 sm:grid-cols-3">
              <div className="rounded-md border border-border-faint bg-bg-inset px-3 py-2.5">
                <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Structured Evidence Available</p>
                <p className="mt-0.5 text-lg font-semibold tabular-nums text-fg">
                  {evidenceAvailability.structuredEvidenceCount} / {evidenceAvailability.total}
                </p>
              </div>
              <div className="rounded-md border border-border-faint bg-bg-inset px-3 py-2.5">
                <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Supporting Events Available</p>
                <p className="mt-0.5 text-lg font-semibold tabular-nums text-fg">
                  {evidenceAvailability.supportingEventsCount} / {evidenceAvailability.total}
                </p>
              </div>
              <div className="rounded-md border border-border-faint bg-bg-inset px-3 py-2.5">
                <p className="text-[11px] uppercase tracking-wide text-fg-subtle">MITRE Mapping Available</p>
                <p className="mt-0.5 text-lg font-semibold tabular-nums text-fg">
                  {evidenceAvailability.mitreMappingCount} / {evidenceAvailability.total}
                </p>
              </div>
            </div>
          </Card>
        </>
      )}

      {/* ---- Section 7: Telemetry Context -- degrades independently of
       * alert data (mirrors TelemetryHealthPage's resilience pattern). ---- */}
      <Card className="mt-4">
        <CardHeader title="Telemetry Context" subtitle="Telemetry observed in the selected bounded dataset -- not total telemetry" />
        {eventsFailed ? (
          <ErrorState title="Unable to retrieve telemetry" onRetry={refresh} />
        ) : eventsLiveState === 'loading' ? (
          <div className="grid grid-cols-2 gap-3 px-5 pb-5 sm:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-14 w-full" />
            ))}
          </div>
        ) : events.length === 0 ? (
          <p className="px-5 pb-5 text-xs text-fg-subtle">No telemetry was returned for the selected window.</p>
        ) : (
          <div className="grid grid-cols-2 gap-3 px-5 pb-5 sm:grid-cols-4">
            <div className="rounded-md border border-border-faint bg-bg-inset px-3 py-2.5">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Events Returned</p>
              <p className="mt-0.5 text-lg font-semibold tabular-nums text-fg">{events.length}</p>
            </div>
            <div className="rounded-md border border-border-faint bg-bg-inset px-3 py-2.5">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Event Types Observed</p>
              <p className="mt-0.5 text-lg font-semibold tabular-nums text-fg">{eventTypeInventory.length}</p>
            </div>
            <div className="rounded-md border border-border-faint bg-bg-inset px-3 py-2.5">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Sources Observed</p>
              <p className="mt-0.5 text-lg font-semibold tabular-nums text-fg">{sourceInventory.length}</p>
            </div>
            <div className="rounded-md border border-border-faint bg-bg-inset px-3 py-2.5">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Latest Event</p>
              <p className="mt-0.5 text-sm font-medium text-fg">{latestEvent ? formatRelativeTime(latestEvent) : '—'}</p>
            </div>
          </div>
        )}
      </Card>

      {/* ---- Section 8: Investigation Insight -- honest limitation,
       * never a fabricated "N alerts investigated" figure. ---- */}
      <Card className="mt-4 p-6">
        <p className="text-sm font-semibold text-fg">Investigation Insight</p>
        <p className="mt-2 text-sm text-fg-muted">
          Investigation completion cannot be measured globally from the current API. AMNIX computes investigation context on
          demand per alert and does not persist an "investigated" flag or a bulk investigation-status endpoint, so no
          investigation-completion count is shown here.
        </p>
        <Link to="/alerts" className="mt-3 inline-flex items-center gap-1.5 text-xs font-medium text-accent-strong hover:text-accent">
          Open the Alert Queue to triage and investigate individual alerts →
        </Link>
      </Card>

      {/* ---- Section 9: Copilot Insight -- honest limitation, never an
       * inferred usage count. ---- */}
      <Card className="mt-4 p-6">
        <p className="text-sm font-semibold text-fg">Copilot Insight</p>
        <p className="mt-2 text-sm text-fg-muted">
          Copilot usage cannot be measured here. Copilot audit records exist per-alert only (no bulk/aggregate audit API), so
          computing a usage metric on this page would require one additional request per alert -- exactly the kind of
          per-row fan-out this page avoids. No Copilot request is made by this page, automatically or otherwise.
        </p>
      </Card>
    </div>
  )
}
