import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, ArrowRight, FileSearch, Bot } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { SeverityBadge, Badge } from '@/components/ui/Badge'
import { ErrorState } from '@/components/ui/ErrorState'
import { Skeleton } from '@/components/ui/Skeleton'
import { Button } from '@/components/ui/Button'
import { useAlertDetail } from '@/features/alerts/useAlertDetail'
import { AlertStatusControl } from '@/features/alerts/components/AlertStatusControl'
import { lookupMitreTechnique } from '@/features/dashboard/mitreRegistry'
import { explainAlertPriority } from '@/features/alerts/priority'
import { getRuleDefinition } from '@/features/rules/ruleRegistry'

const STATUS_TONE: Record<string, 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

export function AlertDetailPage() {
  const { alertId } = useParams<{ alertId: string }>()
  const navigate = useNavigate()
  const { data: alert, isPending, isError, refetch } = useAlertDetail(alertId)

  return (
    <div className="mx-auto max-w-[1000px] px-6 py-6">
      <button
        type="button"
        onClick={() => navigate('/alerts')}
        className="mb-4 flex items-center gap-1.5 text-xs text-fg-subtle transition-colors duration-fast hover:text-fg"
      >
        <ArrowLeft className="size-3.5" strokeWidth={2} aria-hidden="true" />
        Back to Alerts
      </button>

      {isPending && (
        <Card className="p-6">
          <Skeleton className="h-6 w-64" />
          <Skeleton className="mt-3 h-4 w-40" />
          <Skeleton className="mt-6 h-24 w-full" />
        </Card>
      )}

      {isError && !isPending && (
        <Card>
          <ErrorState title="Unable to retrieve this alert" onRetry={() => refetch()} />
        </Card>
      )}

      {alert && (
        <>
          {/* REAL BACKEND DATA -- every field below is GET /alerts/{id} verbatim. */}
          <Card className="p-6">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <SeverityBadge severity={alert.severity} />
                <h1 className="mt-2 text-lg font-semibold text-fg">{alert.title}</h1>
                <p className="mt-1 flex items-center gap-2 font-mono text-xs text-fg-subtle">
                  {/* Step 12H: alert -> rule is only a link when the
                   * rule_id resolves against the real, static rule
                   * inventory -- an unrecognized rule_id is shown as
                   * plain text rather than linking to a fabricated
                   * rule page (see ruleRegistry.ts). */}
                  {getRuleDefinition(alert.rule_id) ? (
                    <Link to={`/rules/${alert.rule_id}`} className="text-accent-strong transition-colors duration-fast hover:text-accent">
                      {alert.rule_id}
                    </Link>
                  ) : (
                    alert.rule_id
                  )}
                  {lookupMitreTechnique(alert.rule_id) && (
                    <span className="text-accent-strong">
                      · {lookupMitreTechnique(alert.rule_id)!.techniqueId} — {lookupMitreTechnique(alert.rule_id)!.name}
                    </span>
                  )}
                </p>
                {/* Explainable triage priority (Step 12G) -- same
                 * severity/status/recency fields as the Alerts queue,
                 * never a hidden score. See features/alerts/priority.ts. */}
                <p className="mt-1 text-xs text-fg-subtle">{explainAlertPriority(alert)}</p>
              </div>
              <Badge tone={STATUS_TONE[alert.status]}>{alert.status}</Badge>
            </div>

            <dl className="mt-6 grid grid-cols-2 gap-4 border-t border-border pt-4 sm:grid-cols-4">
              <div>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Confidence</dt>
                <dd className="mt-0.5 text-sm capitalize text-fg">{alert.confidence}</dd>
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
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Events</dt>
                <dd className="mt-0.5 text-sm text-fg">{alert.source_event_ids.length}</dd>
              </div>
            </dl>

            <p className="mt-4 text-sm text-fg-muted">{alert.description}</p>

            <div className="mt-4 border-t border-border pt-4">
              <p className="mb-2 text-[11px] uppercase tracking-wide text-fg-subtle">Change Status</p>
              <AlertStatusControl alert={alert} />
            </div>
          </Card>

          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Related Events" subtitle={`${alert.source_event_ids.length} source event(s) cited as evidence`} />
            {alert.source_event_ids.length === 0 ? (
              <p className="px-5 pb-5 text-xs text-fg-subtle">No source events recorded for this alert.</p>
            ) : (
              <ul className="divide-y divide-border-faint">
                {alert.source_event_ids.map((eventId) => (
                  <li key={eventId}>
                    <Link
                      to={`/events/${eventId}`}
                      className="flex items-center justify-between px-5 py-2.5 font-mono text-xs text-fg-muted transition-colors duration-fast hover:bg-surface-hover hover:text-accent-strong"
                    >
                      {eventId}
                      <ArrowRight className="size-3.5 shrink-0" strokeWidth={2} aria-hidden="true" />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {/* Step 12G: "Investigate Alert" is the primary analyst path
           * (Alert -> Investigation Workspace -> ... -> Copilot, per the
           * validated workflow) -- Copilot is also reachable from
           * inside that workspace, so nothing is lost by making
           * Investigation the visually primary action here. */}
          <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Button variant="primary" className="justify-center" onClick={() => navigate(`/alerts/${alert.id}/investigation`)}>
              <FileSearch className="size-4" strokeWidth={1.75} aria-hidden="true" />
              Investigate Alert
            </Button>
            <Button variant="secondary" className="justify-center" onClick={() => navigate(`/copilot?alert=${alert.id}`)}>
              <Bot className="size-4" strokeWidth={1.75} aria-hidden="true" />
              Open with Copilot
            </Button>
          </div>
        </>
      )}
    </div>
  )
}
