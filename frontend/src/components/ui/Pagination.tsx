import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from './Button'

/** Previous/Next only -- GET /events and GET /alerts deliberately never
 * return a total count (Step 12B), so this component never claims to
 * know how many pages exist. `hasNext` is a heuristic ("this page was
 * full, so another page might exist"), never a real total -- see each
 * page's own usage for exactly how it's computed.
 */
export function Pagination({
  page,
  hasNext,
  onPrevious,
  onNext,
}: {
  page: number
  hasNext: boolean
  onPrevious: () => void
  onNext: () => void
}) {
  return (
    <div className="flex items-center justify-between border-t border-border px-5 py-3">
      <span className="text-xs text-fg-subtle">Page {page}</span>
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" onClick={onPrevious} disabled={page <= 1}>
          <ChevronLeft className="size-3.5" strokeWidth={2} aria-hidden="true" />
          Previous
        </Button>
        <Button variant="ghost" size="sm" onClick={onNext} disabled={!hasNext}>
          Next
          <ChevronRight className="size-3.5" strokeWidth={2} aria-hidden="true" />
        </Button>
      </div>
    </div>
  )
}
