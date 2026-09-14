import { Link } from 'react-router-dom'
import { FileSearch } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { buildCaseContextQuery } from '@/features/cases/caseNavigationContext'
import { getRuleDefinition } from '@/features/rules/ruleRegistry'
import { explainAlertPriority } from '@/features/alerts/priority'
import type { AlertRead, CaseRead, DetectionSeverity } from '@/types/api'

const STATUS_TONE: Record<AlertRead['status'], 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

const SEVERITY_ORDER: DetectionSeverity[] = ['critical', 'high', 'medium', 'low']

/** Reuses the exact alerts already fetched for this case (useCaseAlerts,
 * shared with Case Detail's own panel and the Overview/Detection
 * snapshot above) -- zero additional requests. Grouped by severity,
 * ordered within each group by the existing Step 12G comparator, never
 * a new one.
 */
export function AlertsPanel({
  caseItem,
  alertsBySeverity,
  onFocusAlert,
}: {
  caseItem: CaseRead
  alertsBySeverity: Record<DetectionSeverity, AlertRead[]>
  onFocusAlert: (alertId: string) => void
}) {
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + alertsBySeverity[s].length, 0)
  const caseContextQuery = buildCaseContextQuery({ caseId: caseItem.id, caseNumber: caseItem.case_number })

  return (
    <Card id="console-alerts" className="scroll-mt-20 overflow-hidden">
      <CardHeader title="Alerts" subtitle="Every alert linked to this case, grouped by severity." />

      {total === 0 ? (
        <EmptyState title="No alerts are linked to this case." />
      ) : (
        <div className="flex flex-col gap-4 px-5 pb-5">
          {SEVERITY_ORDER.filter((s) => alertsBySeverity[s].length > 0).map((severity) => (
            <div key={severity}>
              <p className="mb-2 flex items-center gap-2 text-[11px] uppercase tracking-wide text-fg-subtle">
                <Badge tone={severity} dot>
                  {severity}
                </Badge>
                {alertsBySeverity[severity].length} alert{alertsBySeverity[severity].length === 1 ? '' : 's'}
              </p>
              <div className="flex flex-col gap-2">
                {alertsBySeverity[severity].map((alert) => {
                  const rule = getRuleDefinition(alert.rule_id)
                  const eventCount = alert.source_event_ids.length
                  const evidenceCount = Object.keys(alert.evidence).length
                  return (
                    <div
                      key={alert.id}
                      className="rounded-md border border-border-faint bg-bg-inset px-3 py-3 transition-colors duration-fast hover:border-accent/30"
                    >
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <button type="button" onClick={() => onFocusAlert(alert.id)} className="min-w-0 text-left">
                          <p className="truncate text-sm font-medium text-fg hover:text-accent-strong">{alert.title}</p>
                          <p className="mt-0.5 text-[11px] text-fg-subtle">{explainAlertPriority(alert)}</p>
                        </button>
                        <Badge tone={STATUS_TONE[alert.status]}>{alert.status}</Badge>
                      </div>
                      <p className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-fg-subtle">
                        <span title="Detection rule">{rule ? rule.name : alert.rule_id}</span>
                        <span>{evidenceCount} evidence field{evidenceCount === 1 ? '' : 's'}</span>
                        <span>
                          {eventCount} event{eventCount === 1 ? '' : 's'}
                        </span>
                        <span title={new Date(alert.first_seen).toLocaleString()}>First seen {new Date(alert.first_seen).toLocaleDateString()}</span>
                        <span title={new Date(alert.last_seen).toLocaleString()}>Last seen {new Date(alert.last_seen).toLocaleDateString()}</span>
                      </p>
                      <div className="mt-2.5 flex items-center gap-2">
                        <Link to={`/alerts/${alert.id}/investigation${caseContextQuery}`}>
                          <Button type="button" variant="secondary" size="sm">
                            <FileSearch className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                            Investigate
                          </Button>
                        </Link>
                        <Link to={`/alerts/${alert.id}${caseContextQuery}`}>
                          <Button type="button" variant="ghost" size="sm">
                            Alert Detail
                          </Button>
                        </Link>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
