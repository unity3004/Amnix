import { Check, ArrowRight } from 'lucide-react'
import { CardHeader } from '@/components/ui/Card'
import type { AlertRead } from '@/types/api'
import type { DetectionRuleDefinition } from '@/features/rules/ruleRegistry'
import type { MitreTechnique } from '@/features/dashboard/mitreRegistry'

/** Step 12L: "Is the information needed for analyst triage available?"
 * -- a deterministic checklist over data this page already has in hand
 * (zero additional requests). Each item is a plain boolean fact about
 * this alert's real fetched fields, never a percentage, never a risk
 * score, and never a claim about whether the alert IS malicious.
 * Investigation is listed separately, with a "go" affordance rather than
 * a checkmark, because it is deliberately never auto-fetched here (see
 * AlertDetailPage) -- its availability is structural (the route always
 * exists for a real alert id), not a "data already confirmed" fact like
 * the four items above it.
 */
export function TriageReadiness({
  alert,
  rule,
  mitreTechniques,
}: {
  alert: AlertRead
  rule: DetectionRuleDefinition | null
  mitreTechniques: MitreTechnique[]
}) {
  const items = [
    { label: 'Detection rule identified', available: rule !== null },
    { label: 'Alert evidence available', available: Object.keys(alert.evidence).length > 0 },
    { label: 'Supporting events available', available: alert.source_event_ids.length > 0 },
    { label: 'MITRE context available', available: mitreTechniques.length > 0 },
  ]

  return (
    <>
      <CardHeader
        title="Triage Readiness"
        subtitle="Whether the information needed for analyst triage is available -- not a threat or risk assessment"
      />
      <ul className="flex flex-col gap-2 px-5 pb-4">
        {items.map((item) => (
          <li key={item.label} className="flex items-center gap-2 text-sm">
            {item.available ? (
              <Check className="size-4 shrink-0 text-success" strokeWidth={2.5} aria-hidden="true" />
            ) : (
              <span className="size-4 shrink-0 rounded-full border border-border-strong" aria-hidden="true" />
            )}
            <span className={item.available ? 'text-fg' : 'text-fg-subtle'}>
              {item.label}
              <span className="sr-only">{item.available ? ' -- available' : ' -- not available for this alert'}</span>
            </span>
          </li>
        ))}
        <li className="flex items-center gap-2 text-sm">
          <ArrowRight className="size-4 shrink-0 text-accent-strong" strokeWidth={2.5} aria-hidden="true" />
          <span className="text-fg">
            Investigation available
            <span className="sr-only"> -- open the Investigation Workspace to review</span>
          </span>
        </li>
      </ul>
    </>
  )
}
