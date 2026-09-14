import { Link } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'

export interface BreadcrumbStep {
  label: string
  /** Omitted on the current page's own step, and on any step the caller
   * cannot back up with a real, already-existing route/ID. */
  to?: string
}

/** Step 12Z §12: a real, honest workflow-position trail -- Threat
 * Hunting / Event / Alert / Investigation / Case, but ONLY the levels a
 * given page actually knows to be real. Each caller builds `steps` from
 * data it already has (Step 12U case-navigation context, or the current
 * resource's own id/title) -- this component never fetches anything and
 * never invents a level or an ID. The last step is always the current
 * page: not a link, marked `aria-current="page"`.
 */
export function WorkflowBreadcrumb({ steps }: { steps: BreadcrumbStep[] }) {
  if (steps.length < 2) return null

  return (
    <nav aria-label="Workflow breadcrumb" className="mb-3 flex flex-wrap items-center gap-1.5 text-xs text-fg-subtle">
      {steps.map((step, i) => {
        const isLast = i === steps.length - 1
        return (
          <span key={`${step.label}-${i}`} className="flex items-center gap-1.5">
            {i > 0 && <ChevronRight className="size-3 shrink-0 text-fg-subtle/60" strokeWidth={2} aria-hidden="true" />}
            {!isLast && step.to ? (
              <Link to={step.to} className="transition-colors duration-fast hover:text-accent-strong">
                {step.label}
              </Link>
            ) : (
              <span className={isLast ? 'font-medium text-fg' : undefined} aria-current={isLast ? 'page' : undefined}>
                {step.label}
              </span>
            )}
          </span>
        )
      })}
    </nav>
  )
}
