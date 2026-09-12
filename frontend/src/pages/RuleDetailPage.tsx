import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, ShieldQuestion } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { SkeletonRow } from '@/components/ui/Skeleton'
import { Pagination } from '@/components/ui/Pagination'
import { getRuleDefinition } from '@/features/rules/ruleRegistry'
import { getMitreTechniquesForRule } from '@/features/dashboard/mitreRegistry'
import { useRuleAlerts } from '@/features/rules/useRuleAlerts'
import { AlertRow } from '@/features/alerts/components/AlertRow'

/** Rule Detail (Step 12H). Every field above the "Recent Alerts" divider
 * comes from the static, source-mirrored ruleRegistry.ts (see its own
 * docstring) -- never fetched, never invented. The "Recent Alerts"
 * section is the one part of this page that talks to the real backend,
 * via the existing GET /alerts?rule_id=... (Step 12B) -- fetched only
 * once this specific rule's detail page is open, never for every rule
 * in the explorer list.
 */
export function RuleDetailPage() {
  const { ruleId } = useParams<{ ruleId: string }>()
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const rule = ruleId ? getRuleDefinition(ruleId) : null
  const { alerts, hasNextPage, isPending, isError, refetch } = useRuleAlerts(rule ? ruleId : undefined, page)

  return (
    <div className="mx-auto max-w-[1100px] px-6 py-6">
      <button
        type="button"
        onClick={() => navigate('/rules')}
        className="mb-4 flex items-center gap-1.5 text-xs text-fg-subtle transition-colors duration-fast hover:text-fg"
      >
        <ArrowLeft className="size-3.5" strokeWidth={2} aria-hidden="true" />
        Back to Detection Rules
      </button>

      {!rule ? (
        <Card>
          <EmptyState
            icon={ShieldQuestion}
            title="Rule not found"
            description={`"${ruleId}" does not match any detection rule AMNIX currently evaluates.`}
          />
        </Card>
      ) : (
        <>
          <Card className="p-6">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <SeverityBadge severity={rule.severity} />
                <h1 className="mt-2 text-lg font-semibold text-fg">{rule.name}</h1>
                <p className="mt-1 font-mono text-xs text-fg-subtle">{rule.ruleId}</p>
              </div>
              <Badge tone="success">Active · Application-controlled</Badge>
            </div>

            <p className="mt-4 text-sm text-fg-muted">{rule.description}</p>

            <dl className="mt-4 grid grid-cols-2 gap-4 border-t border-border pt-4 sm:grid-cols-3">
              <div>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Confidence</dt>
                <dd className="mt-0.5 text-sm capitalize text-fg">{rule.confidence}</dd>
              </div>
              <div>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Event Type(s)</dt>
                <dd className="mt-0.5 font-mono text-sm text-fg">{rule.eventTypes.join(', ')}</dd>
              </div>
              {rule.additionalCondition && (
                <div className="sm:col-span-1">
                  <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">Additional Condition</dt>
                  <dd className="mt-0.5 text-sm text-fg">{rule.additionalCondition}</dd>
                </div>
              )}
            </dl>

            <div className="mt-4 border-t border-border pt-4">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">Detection Logic</p>
              <p className="mt-1.5 text-sm text-fg-muted">{rule.detectionLogic}</p>
            </div>

            <div className="mt-4 border-t border-border pt-4">
              <p className="text-[11px] uppercase tracking-wide text-fg-subtle">MITRE mapping associated with this detection rule</p>
              {getMitreTechniquesForRule(rule.ruleId).length === 0 ? (
                <p className="mt-1.5 text-xs text-fg-subtle">No MITRE ATT&CK mapping exists for this rule.</p>
              ) : (
                <ul className="mt-2 flex flex-wrap gap-2">
                  {getMitreTechniquesForRule(rule.ruleId).map((t) => (
                    <li key={t.techniqueId} className="flex items-center gap-1.5 rounded-md border border-border-faint bg-bg-inset px-2.5 py-1.5">
                      <span className="font-mono text-xs font-semibold text-accent-strong">{t.techniqueId}</span>
                      <span className="text-xs text-fg-muted">{t.name}</span>
                      <Badge tone="neutral">{t.tactic}</Badge>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Card>

          <Card className="mt-4 overflow-hidden">
            <CardHeader title="Recent Alerts" subtitle="Real alerts generated by this rule, most recent first -- not a historical total" />
            {isPending && (
              <div className="divide-y divide-border-faint">
                {Array.from({ length: 3 }).map((_, i) => (
                  <SkeletonRow key={i} />
                ))}
              </div>
            )}
            {isError && !isPending && <ErrorState title="Unable to retrieve alerts for this rule" onRetry={() => refetch()} />}
            {!isPending && !isError && alerts.length === 0 && (
              <p className="px-5 pb-5 text-xs text-fg-subtle">No alerts generated by this rule in the current view.</p>
            )}
            {!isPending && !isError && alerts.length > 0 && (
              <>
                <div>
                  {alerts.map((alert) => (
                    <AlertRow key={alert.id} alert={alert} />
                  ))}
                </div>
                <Pagination page={page} hasNext={hasNextPage} onPrevious={() => setPage((p) => Math.max(1, p - 1))} onNext={() => setPage((p) => p + 1)} />
              </>
            )}
          </Card>
        </>
      )}
    </div>
  )
}
