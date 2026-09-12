import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Radio, ShieldAlert, AlertTriangle } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton, SkeletonRow } from '@/components/ui/Skeleton'
import { LiveIndicator } from '@/components/live/LiveIndicator'
import { RefreshButton } from '@/components/live/RefreshButton'
import { SecurityStateBar } from '@/features/dashboard/components/SecurityStateBar'
import { AlertRow } from '@/features/alerts/components/AlertRow'
import { formatRelativeTime, formatCount } from '@/lib/format'
import { useTelemetryHealth, TELEMETRY_WINDOW_OPTIONS } from '@/features/telemetry/useTelemetryHealth'
import { deriveEventTypeInventory, deriveSourceInventory } from '@/features/telemetry/deriveTelemetryInventory'
import { deriveDetectionCoverage, deriveTelemetryToRuleMapping, deriveVisibilityGaps } from '@/features/telemetry/deriveDetectionCoverage'

/** AMNIX Telemetry & Detection Coverage (Step 12I).
 *
 * Exactly two real backend requests per load/refresh/window-change:
 * GET /events and GET /alerts, both bounded by the analyst-selected
 * `since` window (Step 12B's existing filter contract) -- never a
 * per-rule or per-event-type request. Every table/card below is
 * either REAL OBSERVED DATA (event types, sources, alerts -- all
 * derived from those two responses), a STATIC DETECTION DEFINITION
 * (the Step 12H rule registry, reused unmodified), or a DERIVED
 * ANALYST VIEW combining the two (coverage status, visibility gaps) --
 * never a fabricated score, percentage, or historical total.
 */
export function TelemetryHealthPage() {
  const [windowMinutes, setWindowMinutes] = useState(TELEMETRY_WINDOW_OPTIONS[1].minutes)
  const {
    events,
    eventsLiveState,
    eventsHitPageLimit,
    alerts,
    alertsLiveState,
    lastSuccessfulRefreshAt,
    isRefreshing,
    refresh,
  } = useTelemetryHealth(windowMinutes)

  const eventTypeInventory = useMemo(() => deriveEventTypeInventory(events), [events])
  const sourceInventory = useMemo(() => deriveSourceInventory(events), [events])
  const coverage = useMemo(() => deriveDetectionCoverage(events, alerts), [events, alerts])
  const telemetryToRule = useMemo(() => deriveTelemetryToRuleMapping(events), [events])
  const visibilityGaps = useMemo(() => deriveVisibilityGaps(coverage, telemetryToRule), [coverage, telemetryToRule])

  const windowLabel = TELEMETRY_WINDOW_OPTIONS.find((o) => o.minutes === windowMinutes)?.label ?? 'selected window'
  const eventsFailed = eventsLiveState === 'error'
  const alertsFailed = alertsLiveState === 'error'

  if (eventsFailed && alertsFailed) {
    return (
      <div className="mx-auto max-w-[1500px] px-6 py-6">
        <PageHeader title="Telemetry & Detection Coverage" description="Understand what telemetry AMNIX is observing and how current detections depend on it." />
        <Card>
          <ErrorState title="Unable to retrieve telemetry or alert data" onRetry={refresh} />
        </Card>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <PageHeader title="Telemetry & Detection Coverage" description="Understand what telemetry AMNIX is observing and how current detections depend on it." />
        <div className="flex items-center gap-3">
          <label htmlFor="telemetry-window" className="text-xs text-fg-subtle">
            Observation window
          </label>
          <select
            id="telemetry-window"
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
          <LiveIndicator state={eventsLiveState} lastSuccessfulRefreshAt={lastSuccessfulRefreshAt} />
          <RefreshButton onRefresh={refresh} isRefreshing={isRefreshing} />
        </div>
      </div>

      {/* ---- Section 1: Telemetry Overview -- bounded observations, never historical totals ---- */}
      {eventsFailed ? (
        <Card>
          <ErrorState title="Unable to retrieve telemetry" onRetry={refresh} />
        </Card>
      ) : eventsLiveState === 'loading' ? (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full" />
          ))}
        </div>
      ) : (
        <>
          <SecurityStateBar
            items={[
              { label: 'Event Types Observed', value: formatCount(eventTypeInventory.length) },
              { label: 'Sources Observed', value: formatCount(sourceInventory.length) },
              { label: 'Recent Events Returned', value: formatCount(events.length) },
              { label: 'Rules Evaluated Against Observed Types', value: formatCount(coverage.filter((c) => c.telemetryObserved).length) },
            ]}
          />
          <p className="mt-1.5 text-[11px] text-fg-subtle">
            {windowLabel} · bounded to the most recent {events.length}{eventsHitPageLimit ? '+' : ''} event(s) returned by the API — not a historical total.
          </p>

          {/* ---- Section 2: Observed Telemetry ---- */}
          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Observed Telemetry" subtitle={`Event types seen in the ${windowLabel.toLowerCase()} (current API page)`} />
            {eventTypeInventory.length === 0 ? (
              <EmptyState icon={Radio} title="No recent telemetry observed" description="No security events were returned for the selected window." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-border text-[11px] uppercase tracking-wide text-fg-subtle">
                      <th className="px-5 py-2 font-medium">Event Type</th>
                      <th className="px-3 py-2 font-medium">Recent Observation</th>
                      <th className="px-3 py-2 font-medium">Observed Count</th>
                      <th className="px-3 py-2 font-medium">Latest Seen</th>
                      <th className="px-5 py-2 font-medium">Source(s)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-faint">
                    {eventTypeInventory.map((entry) => (
                      <tr key={entry.eventType}>
                        <td className="px-5 py-2.5 font-mono text-fg">{entry.eventType}</td>
                        <td className="px-3 py-2.5">
                          <Badge tone="success">Observed recently</Badge>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-fg-muted">{entry.observedCount}</td>
                        <td className="px-3 py-2.5 text-fg-muted">{formatRelativeTime(entry.latestSeen)}</td>
                        <td className="px-5 py-2.5 text-fg-muted">{entry.sources.join(', ')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          {/* ---- Source distribution (SecurityEventRead.source is a real, required field) ---- */}
          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Telemetry Sources" subtitle="Sources producing telemetry in the selected window" />
            {sourceInventory.length === 0 ? (
              <p className="px-5 pb-5 text-xs text-fg-subtle">No source information available in the selected window.</p>
            ) : (
              <ul className="divide-y divide-border-faint">
                {sourceInventory.map((entry) => (
                  <li key={entry.source} className="flex items-center justify-between px-5 py-2.5 text-xs">
                    <span className="font-mono text-fg">{entry.source}</span>
                    <span className="text-fg-muted">{entry.observedCount} event(s) · latest {formatRelativeTime(entry.latestSeen)}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {/* ---- Section 3: Detection Coverage Map ---- */}
          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Detection Coverage Map" subtitle="Static rule definitions (Step 12H) cross-referenced against telemetry actually observed" />
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-[11px] uppercase tracking-wide text-fg-subtle">
                    <th className="px-5 py-2 font-medium">Rule</th>
                    <th className="px-3 py-2 font-medium">Required Event Type(s)</th>
                    <th className="px-3 py-2 font-medium">Telemetry Status</th>
                    <th className="px-5 py-2 font-medium">Recent Alert Activity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-faint">
                  {coverage.map(({ rule, telemetryObserved, recentAlertCount, hasRecentAlertActivity }) => (
                    <tr key={rule.ruleId}>
                      <td className="px-5 py-2.5">
                        <Link to={`/rules/${rule.ruleId}`} className="font-medium text-accent-strong hover:text-accent">
                          {rule.name}
                        </Link>
                        <p className="font-mono text-[10px] text-fg-subtle">{rule.ruleId}</p>
                      </td>
                      <td className="px-3 py-2.5 font-mono text-fg-muted">{rule.eventTypes.join(', ')}</td>
                      <td className="px-3 py-2.5">
                        <Badge tone={telemetryObserved ? 'success' : 'neutral'}>
                          {telemetryObserved ? 'Telemetry observed recently' : 'No recent telemetry observed'}
                        </Badge>
                      </td>
                      <td className="px-5 py-2.5">
                        <Badge tone={hasRecentAlertActivity ? 'warning' : 'neutral'}>
                          {hasRecentAlertActivity ? `Recent alert activity (${recentAlertCount})` : 'No recent alert activity'}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          {/* ---- Telemetry -> Rule mapping ---- */}
          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Telemetry Dependents" subtitle="For each observed event type, which detection rules depend on it" />
            {telemetryToRule.length === 0 ? (
              <p className="px-5 pb-5 text-xs text-fg-subtle">No event types observed in the selected window.</p>
            ) : (
              <ul className="divide-y divide-border-faint">
                {telemetryToRule.map((entry) => (
                  <li key={entry.eventType} className="px-5 py-2.5 text-xs">
                    <span className="font-mono font-medium text-fg">{entry.eventType}</span>
                    {entry.dependentRules.length === 0 ? (
                      <span className="ml-2 text-fg-subtle">no detection rule depends on this event type</span>
                    ) : (
                      <span className="ml-2 text-fg-muted">
                        →{' '}
                        {entry.dependentRules.map((r, i) => (
                          <span key={r.ruleId}>
                            <Link to={`/rules/${r.ruleId}`} className="text-accent-strong hover:text-accent">
                              {r.ruleId}
                            </Link>
                            {i < entry.dependentRules.length - 1 ? ', ' : ''}
                          </span>
                        ))}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {/* ---- Section 4: Visibility Gaps ---- */}
          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Potential Visibility Gaps" subtitle="Neutral observations only -- absence of recent data does not prove a failure" />
            {visibilityGaps.length === 0 ? (
              <p className="px-5 pb-5 text-xs text-fg-subtle">No potential visibility gaps identified in the selected window.</p>
            ) : (
              <ul className="divide-y divide-border-faint">
                {visibilityGaps.map((gap, i) => (
                  <li key={i} className="flex items-start gap-2 px-5 py-2.5 text-xs text-fg-muted">
                    <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warning" strokeWidth={1.75} aria-hidden="true" />
                    {gap.message}
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}

      {/* ---- Section 5: Recent Detection Activity -- degrades independently of telemetry data ---- */}
      <Card className="mt-4 overflow-hidden">
        <CardHeader title="Recent Detection Activity" subtitle={`Real alerts returned for the ${windowLabel.toLowerCase()} -- not a historical total`} />
        {alertsFailed ? (
          <ErrorState title="Unable to retrieve recent alert activity" onRetry={refresh} />
        ) : alertsLiveState === 'loading' ? (
          <div className="divide-y divide-border-faint">
            {Array.from({ length: 3 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        ) : alerts.length === 0 ? (
          <EmptyState icon={ShieldAlert} title="No recent alert activity" description="No alerts were returned for the selected window." />
        ) : (
          <div>
            {alerts.map((alert) => (
              <AlertRow key={alert.id} alert={alert} />
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
