import { Check, Circle } from 'lucide-react'
import { CardHeader } from '@/components/ui/Card'
import type { InvestigationProgressItem } from '../logic'

/** Read-only checklist -- check icons only ever reflect real, already-
 * fetched data (see deriveInvestigationProgress in logic.ts). No
 * progress percentage, no fabricated "X% complete" claim.
 */
export function InvestigationProgressPanel({ items }: { items: InvestigationProgressItem[] }) {
  return (
    <div className="rounded-lg border border-border bg-surface">
      <CardHeader title="Investigation Progress" subtitle="Read-only indicators -- not a completion percentage." />
      <ul className="flex flex-col gap-2 px-5 pb-5">
        {items.map((item) => (
          <li key={item.key} className="flex items-center gap-2 text-sm">
            {item.complete ? (
              <Check className="size-4 shrink-0 text-success" strokeWidth={2.25} aria-hidden="true" />
            ) : (
              <Circle className="size-4 shrink-0 text-fg-subtle" strokeWidth={1.75} aria-hidden="true" />
            )}
            <span className={item.complete ? 'text-fg' : 'text-fg-subtle'}>{item.label}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
