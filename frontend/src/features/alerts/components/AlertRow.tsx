import { useNavigate } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'
import { SeverityBadge, Badge } from '@/components/ui/Badge'
import { getMitreTechniquesForRule } from '@/features/dashboard/mitreRegistry'
import { getRuleDefinition } from '@/features/rules/ruleRegistry'
import { explainAlertPriority } from '@/features/alerts/priority'
import type { AlertRead } from '@/types/api'

const STATUS_TONE: Record<AlertRead['status'], 'accent' | 'neutral' | 'success' | 'warning'> = {
  new: 'accent',
  acknowledged: 'neutral',
  investigating: 'warning',
  resolved: 'success',
  escalated: 'accent',
}

/** REAL BACKEND DATA -- every field rendered here comes directly from
 * one AlertRead row (GET /alerts). `rule`/`techniques` are the only
 * derived values, both static, application-controlled registry lookups
 * (Step 12H/12E) keyed on the alert's own real rule_id -- never fetched,
 * never invented. Step 12M: fixed a real bug where this row used
 * lookupMitreTechnique() (first match only) instead of
 * getMitreTechniquesForRule() (all matches), silently dropping a
 * technique for multi-mapped rules like encoded_powershell_command --
 * see AlertDetailPage's identical Step 12K fix. Also added two more
 * real, already-fetched triage signals -- evidence availability and the
 * resolved rule name -- and an explicit "Triage" action affordance, all
 * without any additional request.
 */
export function AlertRow({ alert }: { alert: AlertRead }) {
  const navigate = useNavigate()
  const rule = getRuleDefinition(alert.rule_id)
  const techniques = getMitreTechniquesForRule(alert.rule_id)
  const eventCount = alert.source_event_ids.length
  const hasEvidence = Object.keys(alert.evidence).length > 0

  return (
    <button
      type="button"
      onClick={() => navigate(`/alerts/${alert.id}`)}
      className="flex w-full flex-col gap-2 border-b border-border-faint px-5 py-3 text-left transition-colors duration-fast last:border-b-0 hover:bg-surface-hover sm:flex-row sm:items-center sm:gap-4"
    >
      <div className="flex items-center gap-3 sm:contents">
        <SeverityBadge severity={alert.severity} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-fg">{alert.title}</p>
          <p className="flex flex-wrap items-center gap-x-1.5 truncate font-mono text-[11px] text-fg-subtle">
            <span title="Detection rule -- unrecognized rule_id shown as-is, never a fabricated name">
              {rule ? rule.name : alert.rule_id}
            </span>
            <span className="text-accent-strong">
              · {techniques.length > 0 ? techniques.map((t) => t.techniqueId).join(', ') : 'No mapping'}
            </span>
          </p>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 sm:shrink-0 sm:justify-end sm:gap-4">
        <Badge tone={STATUS_TONE[alert.status]}>{alert.status}</Badge>
        {/* Explainable triage priority (Step 12G) -- severity/status/
         * recency, the exact same fields the comparator sorts on, never
         * a hidden score. See features/alerts/priority.ts. */}
        <span className="text-xs text-fg-subtle sm:text-right" title="Why this alert is prioritized">
          {explainAlertPriority(alert)}
        </span>
        {/* Evidence availability (Step 12M) -- whether AlertRead.evidence
         * is non-empty, never an inspection of its contents/meaning. */}
        <span className="text-xs text-fg-subtle" title="Whether structured detection evidence was recorded for this alert">
          {hasEvidence ? 'Evidence available' : 'No structured evidence'}
        </span>
        <span className="font-mono text-xs text-fg-subtle sm:w-20 sm:text-right">
          {eventCount} event{eventCount === 1 ? '' : 's'}
        </span>
        <span className="hidden items-center gap-1 text-xs font-medium text-accent-strong sm:flex">
          Triage
          <ChevronRight className="size-3.5" strokeWidth={2} aria-hidden="true" />
        </span>
      </div>
    </button>
  )
}
