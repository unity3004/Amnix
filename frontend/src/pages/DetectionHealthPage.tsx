import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ShieldQuestion, AlertTriangle } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { LiveIndicator } from '@/components/live/LiveIndicator'
import { RefreshButton } from '@/components/live/RefreshButton'
import { SecurityStateBar } from '@/features/dashboard/components/SecurityStateBar'
import { useTelemetryHealth, TELEMETRY_WINDOW_OPTIONS } from '@/features/telemetry/useTelemetryHealth'
import { deriveDetectionCoverage, deriveTelemetryToRuleMapping } from '@/features/telemetry/deriveDetectionCoverage'
import { deriveRuleActivity } from '@/features/operations/deriveOperationsSummary'
import { deriveRuleObservability, deriveUnknownRuleActivity } from '@/features/detectionHealth/deriveDetectionHealth'
import { DETECTION_RULES } from '@/features/rules/ruleRegistry'
import { formatCount } from '@/lib/format'

const KNOWN_RULE_IDS = new Set(DETECTION_RULES.map((r) => r.ruleId))

/** AMNIX Detection Health (Step 12O).
 *
 * Exactly two real backend requests per load/refresh/window-change --
 * GET /events and GET /alerts, both already existing (Step 12B), both
 * bounded by the analyst-selected observation window. Reuses
 * useTelemetryHealth() (Step 12I) unmodified -- no third data-fetching
 * hook, no per-rule/per-alert/per-event/investigation/Copilot request.
 *
 * Every section is either REAL OBSERVED DATA, a STATIC DETECTION
 * DEFINITION (the Step 12H rule registry / Step 12E MITRE registry,
 * reused unmodified), or a DERIVED ANALYST OBSERVATION (Step 12I's
 * deriveDetectionCoverage/deriveTelemetryToRuleMapping and this step's
 * new evidence-observability + combined-observation-sentence helpers)
 * -- never a fabricated effectiveness, accuracy, true/false-positive,
 * or coverage-percentage claim. See deriveDetectionHealth.ts's own
 * docstring for why that distinction is enforced by construction.
 */
export function DetectionHealthPage() {
  const [windowMinutes, setWindowMinutes] = useState(TELEMETRY_WINDOW_OPTIONS[1].minutes)
  const {
    events,
    eventsLiveState,
    alerts,
    alertsLiveState,
    lastSuccessfulRefreshAt,
    isRefreshing,
    refresh,
  } = useTelemetryHealth(windowMinutes)

  const eventsFailed = eventsLiveState === 'error'
  const alertsFailed = alertsLiveState === 'error'
  const eventsLoading = eventsLiveState === 'loading'
  const alertsLoading = alertsLiveState === 'loading'

  // Never let a failed source silently masquerade as "zero observed" --
  // an empty array is only fed to the derive functions when that
  // source's own load genuinely succeeded (or is still pending, ahead
  // of its own loading-skeleton branch below).
  const coverage = useMemo(
    () => deriveDetectionCoverage(eventsFailed ? [] : events, alertsFailed ? [] : alerts),
    [events, alerts, eventsFailed, alertsFailed],
  )
  const observability = useMemo(
    () => deriveRuleObservability(coverage, alertsFailed ? [] : alerts),
    [coverage, alerts, alertsFailed],
  )
  const unknownRuleActivity = useMemo(
    () => (alertsFailed ? [] : deriveUnknownRuleActivity(alerts, KNOWN_RULE_IDS)),
    [alerts, alertsFailed],
  )
  const ruleActivity = useMemo(() => deriveRuleActivity(alerts), [alerts])
  const telemetryToRule = useMemo(() => deriveTelemetryToRuleMapping(events), [events])
  const maxRuleActivityCount = Math.max(1, ...ruleActivity.map((r) => r.recentAlertCount))

  const windowLabel = TELEMETRY_WINDOW_OPTIONS.find((o) => o.minutes === windowMinutes)?.label ?? 'selected window'

  const rulesWithAlertActivity = coverage.filter((c) => c.hasRecentAlertActivity).length
  const rulesWithTelemetry = coverage.filter((c) => c.telemetryObserved).length
  const rulesWithTelemetryNoAlerts = coverage.filter((c) => c.telemetryObserved && !c.hasRecentAlertActivity).length
  const observedEventTypeCount = telemetryToRule.length

  if (alertsFailed && eventsFailed) {
    return (
      <div className="mx-auto max-w-[1500px] px-6 py-6">
        <PageHeader
          title="Detection Health"
          description="Observable relationships between telemetry, detection rules, and recent alert activity."
        />
        <Card>
          <ErrorState title="Detection health data could not be loaded" onRetry={refresh} />
        </Card>
      </div>
    )
  }

  const isFullyLoading = (eventsLoading && !events.length) || (alertsLoading && !alerts.length)
  const isEmpty = !eventsFailed && !alertsFailed && !eventsLoading && !alertsLoading && events.length === 0 && alerts.length === 0

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <PageHeader
          title="Detection Health"
          description="Observable relationships between telemetry, detection rules, and recent alert activity."
        />
        <div className="flex items-center gap-3">
          <label htmlFor="detection-health-window" className="text-xs text-fg-subtle">
            Observation window
          </label>
          <select
            id="detection-health-window"
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

      {(eventsFailed || alertsFailed) && (
        <div className="mb-4 flex items-center gap-2 rounded-md border border-warning/30 bg-warning-dim px-4 py-2.5 text-xs text-warning">
          <AlertTriangle className="size-3.5 shrink-0" strokeWidth={1.75} aria-hidden="true" />
          {eventsFailed
            ? 'Telemetry could not be retrieved for this refresh -- telemetry-dependent columns below are marked "Unavailable", not zero.'
            : 'Alert activity could not be retrieved for this refresh -- alert-dependent columns below are marked "Unavailable", not zero.'}
        </div>
      )}

      {isFullyLoading ? (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full" />
          ))}
        </div>
      ) : (
        <>
          {/* The Detection Rule Observability table below is grounded in
           * the static rule registry, not in whether any telemetry/alert
           * data exists -- "No dependent telemetry observed in this
           * view" is itself a valid, informative per-row observation
           * (Phase 7), so an empty bounded dataset never hides the
           * table. This card is purely an additional, honest heads-up
           * when there is genuinely nothing in either bounded response. */}
          {isEmpty && (
            <Card className="mb-4">
              <EmptyState
                icon={ShieldQuestion}
                title="No detection activity is available for the selected view."
                description="Try widening the observation window."
              />
            </Card>
          )}

          {!eventsFailed && !alertsFailed && (
            <>
              <SecurityStateBar
                items={[
                  { label: 'Rules in Registry', value: formatCount(DETECTION_RULES.length) },
                  { label: 'Rules with Recent Alert Activity', value: formatCount(rulesWithAlertActivity) },
                  { label: 'Rules with Observed Telemetry', value: formatCount(rulesWithTelemetry) },
                  { label: 'Rules with Telemetry but No Recent Alerts', value: formatCount(rulesWithTelemetryNoAlerts) },
                  { label: 'Observed Event Types', value: formatCount(observedEventTypeCount) },
                ]}
              />
              <p className="mt-1.5 text-[11px] text-fg-subtle">
                Based on {events.length} event(s) and {alerts.length} alert(s) returned for the {windowLabel.toLowerCase()} -- this view does
                not represent historical totals.
              </p>
            </>
          )}

          {/* ---- Detection Rule Observability ---- */}
          <Card className="mt-4 overflow-hidden">
            <CardHeader
              title="Detection Rule Observability"
              subtitle="Observable relationships between each rule's dependent telemetry and recent alert activity -- not a measure of rule effectiveness"
            />
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-[11px] uppercase tracking-wide text-fg-subtle">
                    <th className="px-5 py-2 font-medium">Rule</th>
                    <th className="px-3 py-2 font-medium">Event Types</th>
                    <th className="px-3 py-2 font-medium">Telemetry Observed</th>
                    <th className="px-3 py-2 font-medium">Recent Alerts</th>
                    <th className="px-3 py-2 font-medium">Evidence Observed</th>
                    <th className="px-3 py-2 font-medium">MITRE</th>
                    <th className="px-5 py-2 font-medium">Observation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-faint">
                  {observability.map((row) => (
                    <tr key={row.rule.ruleId}>
                      <td className="px-5 py-2.5">
                        <Link to={`/rules/${row.rule.ruleId}`} className="font-medium text-accent-strong hover:text-accent">
                          {row.rule.name}
                        </Link>
                        <p className="font-mono text-[10px] text-fg-subtle">{row.rule.ruleId}</p>
                      </td>
                      <td className="px-3 py-2.5 font-mono text-fg-muted">{row.rule.eventTypes.join(', ')}</td>
                      <td className="px-3 py-2.5">
                        {eventsFailed ? (
                          <span className="italic text-fg-subtle">Unavailable</span>
                        ) : (
                          <Badge tone={row.telemetryObserved ? 'success' : 'neutral'}>
                            {row.telemetryObserved ? 'Observed' : 'Not observed'}
                          </Badge>
                        )}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-fg">
                        {alertsFailed ? <span className="italic text-fg-subtle">Unavailable</span> : row.recentAlertCount}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-fg-muted">
                        {alertsFailed ? (
                          <span className="italic text-fg-subtle">Unavailable</span>
                        ) : (
                          `${row.evidence.evidenceBearingAlerts} / ${row.evidence.alertsReturned}`
                        )}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-fg-subtle">
                        {row.mitreTechniques.length > 0 ? row.mitreTechniques.map((t) => t.techniqueId).join(', ') : 'No mapping'}
                      </td>
                      <td className="px-5 py-2.5 text-fg-muted">
                        {eventsFailed && !alertsFailed
                          ? `Telemetry data unavailable in this view; recent alerts: ${row.recentAlertCount}.`
                          : alertsFailed && !eventsFailed
                            ? `Alert activity data unavailable in this view; telemetry ${row.telemetryObserved ? 'observed' : 'not observed'}.`
                            : row.observation}
                      </td>
                    </tr>
                  ))}
                  {unknownRuleActivity.map((entry) => (
                    <tr key={entry.ruleId} className="bg-bg-inset/40">
                      <td className="px-5 py-2.5">
                        <span className="font-mono text-fg-muted" title="Unrecognized rule_id -- shown as-is, never a fabricated name">
                          {entry.ruleId}
                        </span>
                        <p className="text-[10px] text-fg-subtle">No registry metadata available</p>
                      </td>
                      <td className="px-3 py-2.5 text-fg-subtle">—</td>
                      <td className="px-3 py-2.5 text-fg-subtle">—</td>
                      <td className="px-3 py-2.5 font-mono text-fg">{entry.recentAlertCount}</td>
                      <td className="px-3 py-2.5 text-fg-subtle">—</td>
                      <td className="px-3 py-2.5 text-fg-subtle">—</td>
                      <td className="px-5 py-2.5 text-fg-muted">
                        Recent alert activity observed for an unrecognized rule_id; no registry metadata available.
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          {/* ---- Recent alert activity by detection rule ---- */}
          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Recent Alert Activity by Detection Rule" subtitle="Based on alerts returned for the selected window -- not a ranking of rule quality" />
            {alertsFailed ? (
              <ErrorState title="Unable to retrieve recent alert activity" onRetry={refresh} />
            ) : ruleActivity.length === 0 ? (
              <p className="px-5 pb-5 text-xs text-fg-subtle">No alerts were returned for the selected window.</p>
            ) : (
              <ul className="divide-y divide-border-faint">
                {ruleActivity.map((entry) => (
                  <li key={entry.ruleId} className="flex items-center gap-3 px-5 py-2.5 text-xs">
                    <span className="w-48 shrink-0 truncate text-fg" title={entry.ruleId}>
                      {entry.ruleName ?? entry.ruleId}
                    </span>
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg-inset">
                      <div
                        className="h-full rounded-full bg-accent"
                        style={{ width: `${(entry.recentAlertCount / maxRuleActivityCount) * 100}%` }}
                      />
                    </div>
                    <span className="w-10 shrink-0 text-right font-mono text-fg-muted">{entry.recentAlertCount}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {/* ---- Event type coverage ---- */}
          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Event Type Coverage" subtitle="Observed telemetry types and the detection rules that depend on them" />
            {eventsFailed ? (
              <ErrorState title="Unable to retrieve telemetry" onRetry={refresh} />
            ) : telemetryToRule.length === 0 ? (
              <p className="px-5 pb-5 text-xs text-fg-subtle">No event types observed in the selected window.</p>
            ) : (
              <ul className="divide-y divide-border-faint">
                {telemetryToRule.map((entry) => (
                  <li key={entry.eventType} className="px-5 py-2.5 text-xs">
                    <span className="font-mono font-medium text-fg">{entry.eventType}</span>
                    {entry.dependentRules.length === 0 ? (
                      <span className="ml-2 text-fg-subtle">Observed telemetry type with no rule dependency in the current registry.</span>
                    ) : (
                      <span className="ml-2 text-fg-muted">
                        →{' '}
                        {entry.dependentRules.map((r, i) => (
                          <span key={r.ruleId}>
                            <Link to={`/rules/${r.ruleId}`} className="text-accent-strong hover:text-accent">
                              {r.name}
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
        </>
      )}
    </div>
  )
}
