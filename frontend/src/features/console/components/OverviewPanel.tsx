import { CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import type { CaseRead } from '@/types/api'
import type { DetectionSnapshot } from '../logic'

/** Executive operational summary -- three sub-sections, each built ONLY
 * from data this page already fetched: Incident Snapshot (raw Case
 * fields), Detection Snapshot (derived from linked alerts, see
 * deriveDetectionSnapshot), Investigation Snapshot (what the focused
 * alert's own investigation actually returned, never a fabricated
 * progress claim).
 */
export function OverviewPanel({
  caseItem,
  detectionSnapshot,
  focusedAlertTitle,
  investigationLoaded,
  timelineEventCount,
  hasFindings,
  hasEntities,
}: {
  caseItem: CaseRead
  detectionSnapshot: DetectionSnapshot
  focusedAlertTitle: string | null
  investigationLoaded: boolean
  timelineEventCount: number
  hasFindings: boolean
  hasEntities: boolean
}) {
  return (
    <section id="console-overview" aria-labelledby="console-overview-heading" className="scroll-mt-20">
      <h2 id="console-overview-heading" className="sr-only">
        Overview
      </h2>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-border bg-surface">
          <CardHeader title="Incident Snapshot" subtitle="Case metadata" />
          <dl className="grid grid-cols-2 gap-3 px-5 pb-5 text-sm">
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Status</dt>
              <dd className="mt-0.5 text-fg">{caseItem.status}</dd>
            </div>
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Priority</dt>
              <dd className="mt-0.5 capitalize text-fg">{caseItem.priority}</dd>
            </div>
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Severity</dt>
              <dd className="mt-0.5 capitalize text-fg">{caseItem.severity ?? 'None (no linked alerts)'}</dd>
            </div>
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Owner</dt>
              <dd className="mt-0.5 truncate font-mono text-xs text-fg">{caseItem.owner_id ?? 'Unassigned'}</dd>
            </div>
          </dl>
        </div>

        <div className="rounded-lg border border-border bg-surface">
          <CardHeader title="Detection Snapshot" subtitle="Derived from linked alerts" />
          <dl className="grid grid-cols-2 gap-3 px-5 pb-5 text-sm">
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Linked Alerts</dt>
              <dd className="mt-0.5 text-fg">{detectionSnapshot.linkedAlertCount}</dd>
            </div>
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Highest Severity</dt>
              <dd className="mt-0.5">
                {detectionSnapshot.highestSeverity ? (
                  <Badge tone={detectionSnapshot.highestSeverity} dot>
                    {detectionSnapshot.highestSeverity}
                  </Badge>
                ) : (
                  <span className="text-fg-subtle">None</span>
                )}
              </dd>
            </div>
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Distinct Rules</dt>
              <dd className="mt-0.5 text-fg">{detectionSnapshot.distinctRuleCount}</dd>
            </div>
            <div>
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Distinct Events</dt>
              <dd className="mt-0.5 text-fg">{detectionSnapshot.distinctEventCount}</dd>
            </div>
          </dl>
        </div>

        <div className="rounded-lg border border-border bg-surface">
          <CardHeader
            title="Investigation Snapshot"
            subtitle={focusedAlertTitle ? `Focused on: ${focusedAlertTitle}` : 'No alert focused yet'}
          />
          <dl className="grid grid-cols-1 gap-2 px-5 pb-5 text-sm">
            <div className="flex items-center justify-between">
              <dt className="text-fg-subtle">Timeline events available</dt>
              <dd className="text-fg">{investigationLoaded ? timelineEventCount : '—'}</dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-fg-subtle">Findings available</dt>
              <dd className="text-fg">{investigationLoaded ? (hasFindings ? 'Yes' : 'None extracted') : '—'}</dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-fg-subtle">Entities available</dt>
              <dd className="text-fg">{investigationLoaded ? (hasEntities ? 'Yes' : 'None extracted') : '—'}</dd>
            </div>
          </dl>
        </div>
      </div>
    </section>
  )
}
