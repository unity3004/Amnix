import { Link } from 'react-router-dom'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { getMitreTechniquesForRule } from '@/features/dashboard/mitreRegistry'
import { getRuleDefinition } from '@/features/rules/ruleRegistry'
import type { RuleParticipation } from '../logic'

/** Every detection rule actually involved in this case's linked alerts
 * -- static rule definitions from the existing ruleRegistry (Step 12H),
 * cross-referenced only against alerts already fetched for this case.
 * No per-rule request; the registry is a static, in-memory mirror of
 * the real backend rule classes.
 */
export function DetectionRulesPanel({ rules }: { rules: RuleParticipation[] }) {
  return (
    <Card className="overflow-hidden">
      <CardHeader title="Participating Detection Rules" subtitle="Rules that produced this case's linked alerts." />
      {rules.length === 0 ? (
        <EmptyState title="No detection rules are represented in this case yet." />
      ) : (
        <ul className="divide-y divide-border-faint">
          {rules.map(({ ruleId, alerts, hasObservedEvidence }) => {
            const rule = getRuleDefinition(ruleId)
            const techniques = getMitreTechniquesForRule(ruleId)
            return (
              <li key={ruleId} className="px-5 py-4">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    {rule ? (
                      <Link to={`/rules/${ruleId}`} className="text-sm font-semibold text-accent-strong hover:text-accent">
                        {rule.name}
                      </Link>
                    ) : (
                      <span className="text-sm font-semibold text-fg" title="Unrecognized rule_id">
                        {ruleId}
                      </span>
                    )}
                    <p className="font-mono text-[11px] text-fg-subtle">{ruleId}</p>
                  </div>
                  {rule && <Badge tone={rule.severity}>{rule.severity}</Badge>}
                </div>

                {rule && <p className="mt-2 text-xs text-fg-muted">{rule.detectionLogic}</p>}

                <p className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-fg-subtle">
                  <span>
                    {alerts.length} observed alert{alerts.length === 1 ? '' : 's'}
                  </span>
                  {rule && <span>Telemetry: {rule.eventTypes.join(', ')}</span>}
                  <span>{hasObservedEvidence ? 'Evidence observed' : 'No structured evidence observed'}</span>
                </p>

                {techniques.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {techniques.map((t) => (
                      <span key={t.techniqueId} className="rounded-sm border border-border-faint bg-bg-inset px-1.5 py-0.5 font-mono text-[10px] text-accent-strong">
                        {t.techniqueId}
                      </span>
                    ))}
                  </div>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </Card>
  )
}
