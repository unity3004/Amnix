import { Link } from 'react-router-dom'
import { ArrowRight, CheckCircle2 } from 'lucide-react'
import { CardHeader } from '@/components/ui/Card'
import type { Recommendation } from '../logic'

/** Deterministic only (see deriveRecommendations in logic.ts) -- every
 * item here is a plain if/then over real Case/Alert/Note state, never
 * AI-generated, never a Copilot call. Each recommendation links
 * somewhere real: an existing page, or an in-page section already
 * rendered on this same console.
 */
export function RecommendationsPanel({ recommendations }: { recommendations: Recommendation[] }) {
  return (
    <div className="rounded-lg border border-border bg-surface">
      <CardHeader title="Next Recommended Actions" subtitle="Derived from current case state." />
      {recommendations.length === 0 ? (
        <div className="flex items-center gap-2 px-5 pb-5 text-sm text-fg-subtle">
          <CheckCircle2 className="size-4 shrink-0 text-success" strokeWidth={2} aria-hidden="true" />
          No outstanding recommendations.
        </div>
      ) : (
        <ul className="flex flex-col gap-1.5 px-5 pb-5">
          {recommendations.map((rec) => (
            <li key={rec.key}>
              {rec.href ? (
                <Link
                  to={rec.href}
                  className="flex items-center justify-between gap-2 rounded-md border border-border-faint bg-bg-inset px-3 py-2 text-xs text-fg transition-colors duration-fast hover:border-accent/30 hover:text-accent-strong"
                >
                  {rec.text}
                  <ArrowRight className="size-3.5 shrink-0" strokeWidth={2} aria-hidden="true" />
                </Link>
              ) : (
                <button
                  type="button"
                  onClick={() => document.getElementById(rec.scrollToId as string)?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
                  className="flex w-full items-center justify-between gap-2 rounded-md border border-border-faint bg-bg-inset px-3 py-2 text-left text-xs text-fg transition-colors duration-fast hover:border-accent/30 hover:text-accent-strong"
                >
                  {rec.text}
                  <ArrowRight className="size-3.5 shrink-0" strokeWidth={2} aria-hidden="true" />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
