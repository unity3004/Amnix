import { CardHeader } from '@/components/ui/Card'
import type { AlertRead, InvestigationSummary } from '@/types/api'

/** Section B: a concise analyst summary built entirely from REAL DATA --
 * the Alert's own stored fields plus InvestigationSummary (a
 * deterministic, template-generated computation over the alert's
 * related events -- see backend/app/schemas/investigation.py -- NEVER
 * an AI summary, and NEVER a numeric threat/risk score, which this
 * workspace deliberately never introduces anywhere).
 */
export function AlertSummaryPanel({ alert, summary }: { alert: AlertRead; summary: InvestigationSummary }) {
  return (
    <div>
      <CardHeader title="Alert Summary" subtitle="What triggered this alert, from the alert's own stored data" />
      <div className="px-5 pb-5">
        <p className="text-sm text-fg-muted">{alert.description}</p>

        <dl className="mt-4 grid grid-cols-2 gap-4 border-t border-border pt-4 sm:grid-cols-4">
          <div>
            <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Detection Rule</dt>
            <dd className="mt-0.5 font-mono text-sm text-fg">{alert.rule_id}</dd>
          </div>
          <div>
            <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Severity</dt>
            <dd className="mt-0.5 text-sm capitalize text-fg">{alert.severity}</dd>
          </div>
          <div>
            <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Confidence</dt>
            <dd className="mt-0.5 text-sm capitalize text-fg">{alert.confidence}</dd>
          </div>
          <div>
            <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Status</dt>
            <dd className="mt-0.5 text-sm capitalize text-fg">{alert.status}</dd>
          </div>
        </dl>

        <div className="mt-4 border-t border-border pt-4">
          <p className="text-[11px] uppercase tracking-wide text-fg-subtle">
            Investigation Summary <span className="normal-case text-fg-subtle/70">(deterministic, backend-computed -- not an AI summary)</span>
          </p>
          <p className="mt-1.5 text-sm text-fg">{summary.text}</p>
          <dl className="mt-3 grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Event Count</dt>
              <dd className="mt-0.5 text-sm text-fg">{summary.event_count}</dd>
            </div>
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Unique Hosts</dt>
              <dd className="mt-0.5 text-sm text-fg">{summary.unique_host_count}</dd>
            </div>
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Unique Users</dt>
              <dd className="mt-0.5 text-sm text-fg">{summary.unique_user_count}</dd>
            </div>
            {summary.timespan_seconds !== null && (
              <div>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Timespan</dt>
                <dd className="mt-0.5 text-sm text-fg">{Math.round(summary.timespan_seconds)}s</dd>
              </div>
            )}
          </dl>
        </div>
      </div>
    </div>
  )
}
